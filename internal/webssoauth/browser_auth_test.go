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
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/okta/okta-aws-cli/v2/internal/config"
)

func TestBuildAuthorizeURL(t *testing.T) {
	cfg, err := config.NewConfig(&config.Attributes{
		OrgDomain: "example.okta.com",
		OIDCAppID: "test-client-id",
	})
	if err != nil {
		t.Fatalf("NewConfig() error: %v", err)
	}

	w := &WebSSOAuthentication{config: cfg}

	authorizeURL := w.buildAuthorizeURL("http://127.0.0.1:8080/callback", "test-challenge", "test-state")

	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	if u.Scheme != "https" {
		t.Errorf("scheme: got %q, want %q", u.Scheme, "https")
	}
	if u.Host != "example.okta.com" {
		t.Errorf("host: got %q, want %q", u.Host, "example.okta.com")
	}
	if u.Path != "/oauth2/v1/authorize" {
		t.Errorf("path: got %q, want %q", u.Path, "/oauth2/v1/authorize")
	}

	q := u.Query()
	tests := map[string]string{
		"client_id":             "test-client-id",
		"response_type":         "code",
		"scope":                 "openid okta.apps.sso okta.apps.read okta.users.read.self",
		"redirect_uri":          "http://127.0.0.1:8080/callback",
		"state":                 "test-state",
		"code_challenge":        "test-challenge",
		"code_challenge_method": "S256",
	}
	for key, want := range tests {
		if got := q.Get(key); got != want {
			t.Errorf("param %q: got %q, want %q", key, got, want)
		}
	}
}

func TestGeneratePKCE(t *testing.T) {
	pkce, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE() error: %v", err)
	}

	// RFC 7636: code_verifier must be 43-128 characters
	if len(pkce.CodeVerifier) < 43 || len(pkce.CodeVerifier) > 128 {
		t.Errorf("code_verifier length %d not in range [43, 128]", len(pkce.CodeVerifier))
	}

	// Verify code_challenge is SHA256(code_verifier) base64url-encoded
	h := sha256.Sum256([]byte(pkce.CodeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	if pkce.CodeChallenge != expected {
		t.Errorf("code_challenge mismatch: got %q, want %q", pkce.CodeChallenge, expected)
	}
}

func TestGeneratePKCEUniqueness(t *testing.T) {
	pkce1, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE() error: %v", err)
	}
	pkce2, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE() error: %v", err)
	}

	if pkce1.CodeVerifier == pkce2.CodeVerifier {
		t.Error("two calls to generatePKCE() produced the same code_verifier")
	}
}
