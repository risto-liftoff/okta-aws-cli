/*
 * Copyright (c) 2022-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package webssoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"time"

	brwsr "github.com/pkg/browser"

	"github.com/okta/okta-aws-cli/v2/internal/okta"
	"github.com/okta/okta-aws-cli/v2/internal/utils"
)

// callbackPorts are uncommon ports tried in order for the localhost OAuth
// callback server. Each port that might be used must be registered as a
// redirect URI in the Okta OIDC app (e.g. http://127.0.0.1:29219/callback).
var callbackPorts = []int{29219, 30841, 31425, 32587, 33149, 34762, 35918, 36043, 37651, 38297}

// callbackResult holds the result from the OAuth callback.
type callbackResult struct {
	code  string
	state string
	err   error
}

// authorizeWithBrowser performs the Authorization Code + PKCE flow:
// 1. Generate PKCE parameters
// 2. Start localhost HTTP server
// 3. Open browser to Okta's /oauth2/v1/authorize endpoint
// 4. Wait for the callback with the authorization code
// 5. Exchange the code for tokens
func (w *WebSSOAuthentication) authorizeWithBrowser() (*okta.AccessToken, error) {
	pkce, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE parameters: %w", err)
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("generating state parameter: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	listener, err := listenCallbackPort()
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	resultCh := make(chan callbackResult, 1)

	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query()
		if errParam := q.Get("error"); errParam != "" {
			errDesc := q.Get("error_description")
			resultCh <- callbackResult{
				err: fmt.Errorf("authorization error: %s - %s", errParam, errDesc),
			}
			_, _ = fmt.Fprintf(rw, "<html><body><h1>Authorization Failed</h1><p>%s: %s</p><p>You may close this window.</p></body></html>",
				html.EscapeString(errParam), html.EscapeString(errDesc))
			return
		}

		code := q.Get("code")
		returnedState := q.Get("state")

		if code == "" {
			resultCh <- callbackResult{
				err: fmt.Errorf("no authorization code in callback"),
			}
			_, _ = fmt.Fprint(rw, "<html><body><h1>Error</h1><p>No authorization code received.</p></body></html>")
			return
		}

		resultCh <- callbackResult{code: code, state: returnedState}
		_, _ = fmt.Fprint(rw, "<html><body><h1>Authorization Successful</h1><p>You may close this window and return to the CLI.</p></body></html>")
	})

	server := &http.Server{Handler: handler}

	go func() {
		if sErr := server.Serve(listener); sErr != nil && sErr != http.ErrServerClosed {
			resultCh <- callbackResult{err: fmt.Errorf("localhost server error: %w", sErr)}
		}
	}()

	authorizeURL := w.buildAuthorizeURL(redirectURI, pkce.CodeChallenge, state)

	w.consolePrint("Opening browser for Okta authorization...\n\n%s\n\n", authorizeURL)
	w.openBrowserToURL(authorizeURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var result callbackResult
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		result = callbackResult{err: fmt.Errorf("timed out waiting for authorization callback")}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	if result.err != nil {
		return nil, result.err
	}

	if result.state != state {
		return nil, fmt.Errorf("state mismatch: possible CSRF attack")
	}

	return w.exchangeCodeForTokens(result.code, redirectURI, pkce.CodeVerifier)
}

// buildAuthorizeURL constructs the /oauth2/v1/authorize URL with all required parameters.
func (w *WebSSOAuthentication) buildAuthorizeURL(redirectURI, codeChallenge, state string) string {
	clientID := w.config.OIDCAppID()
	params := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"scope":                 {"openid okta.apps.sso okta.apps.read okta.users.read.self"},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return fmt.Sprintf("https://%s/oauth2/v1/authorize?%s", w.config.OrgDomain(), params.Encode())
}

// exchangeCodeForTokens exchanges an authorization code for access/ID tokens.
func (w *WebSSOAuthentication) exchangeCodeForTokens(code, redirectURI, codeVerifier string) (*okta.AccessToken, error) {
	clientID := w.config.OIDCAppID()
	apiURL := fmt.Sprintf(okta.OAuthV1TokenEndpointFormat, w.config.OrgDomain())

	data := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Add(utils.Accept, utils.ApplicationJSON)
	req.Header.Add(utils.ContentType, utils.ApplicationXFORM)
	req.Header.Add(utils.UserAgentHeader, w.config.UserAgent())
	req.Header.Add(utils.XOktaAWSCLIOperationHeader, utils.XOktaAWSCLIWebOperation)

	resp, err := w.config.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := okta.NewAPIError(resp); err != nil {
		return nil, err
	}

	at := &okta.AccessToken{}
	if err := json.NewDecoder(resp.Body).Decode(at); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	return at, nil
}

// errAllPortsBusy is returned when no callback port could be bound.
var errAllPortsBusy = fmt.Errorf("all browser auth callback ports are in use")

// listenCallbackPort starts an IPv4 loopback-only TCP listener for the OAuth
// callback. It tries each port in callbackPorts and returns errAllPortsBusy
// if none are available.
func listenCallbackPort() (net.Listener, error) {
	for _, p := range callbackPorts {
		l, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			return l, nil
		}
	}

	return nil, errAllPortsBusy
}

// openBrowserToURL opens the given URL using the configured browser strategy.
func (w *WebSSOAuthentication) openBrowserToURL(targetURL string) {
	if w.config.OpenBrowserCommand() != "" {
		bArgs, err := splitArgs(w.config.OpenBrowserCommand())
		if err != nil {
			w.consolePrint("Browser command %q is invalid: %v\n", w.config.OpenBrowserCommand(), err)
			return
		}
		bArgs = append(bArgs, targetURL)
		cmd := osexec.Command(bArgs[0], bArgs[1:]...)
		out, err := cmd.Output()
		if err != nil {
			w.consolePrint("Failed to open URL with given browser: %v\n", err)
			w.consolePrint("  %s\n", strings.Join(bArgs, " "))
		}
		if len(out) > 0 {
			w.consolePrint("browser output:\n%s\n", string(out))
		}
		return
	}

	brwsr.Stdout = os.Stderr
	if err := brwsr.OpenURL(targetURL); err != nil {
		w.consolePrint("Failed to open URL with system browser: %v\nPlease open the URL manually.\n", err)
	}
}

// pkceParams holds the PKCE code verifier and challenge pair.
type pkceParams struct {
	CodeVerifier  string
	CodeChallenge string
}

// generatePKCE generates a PKCE code_verifier and the corresponding
// code_challenge (base64url-encoded SHA256 hash) per RFC 7636.
func generatePKCE() (*pkceParams, error) {
	// 32 bytes -> 43 base64url characters (no padding)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, err
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &pkceParams{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}, nil
}
