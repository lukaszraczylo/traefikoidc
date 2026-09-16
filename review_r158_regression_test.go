package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// R158 review-round regressions.

// TestR158_DiscoveredSplitHostEndpointsPreserved guards the removal of the
// same-host pin on the discovered token/revocation endpoints (main.go
// updateMetadataEndpoints). The pin cleared any token endpoint on a
// different host than providerURL, but mainstream providers split them
// (Google: issuer accounts.google.com, token_endpoint
// oauth2.googleapis.com) — so the real endpoint was discarded, tokenURL
// stayed empty and every code exchange failed. SSRF defense is still
// applied via validateDiscoveredEndpoint.
// Fail-on-old: the split-host token/revoke URLs are cleared.
func TestR158_DiscoveredSplitHostEndpointsPreserved(t *testing.T) {
	tObj := &TraefikOidc{
		logger:      GetSingletonNoOpLogger(),
		providerURL: "https://accounts.google.com",
	}

	meta := &ProviderMetadata{
		Issuer:    "https://accounts.google.com",
		AuthURL:   "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:  "https://oauth2.googleapis.com/token",  // split host
		RevokeURL: "https://oauth2.googleapis.com/revoke", // split host
	}

	tObj.updateMetadataEndpoints(meta)

	if meta.TokenURL == "" {
		t.Error("split-host discovered token endpoint must be preserved; got empty")
	}
	if meta.RevokeURL == "" {
		t.Error("split-host discovered revocation endpoint must be preserved; got empty")
	}
}

// TestR158_ExchangeTokensRejectsBlankAccessToken guards the RFC 6749 §5.1
// presence gate in exchangeTokens (helpers.go). A 200 response must
// carry an access_token; previously any JSON-decodable 200 body was
// treated as success even with a blank token, and each caller had to
// re-check "AccessToken == \"\"" (several paths missed it).
// Fail-on-old: a 200 with no access_token returns success (nil error).
func TestR158_ExchangeTokensRejectsBlankAccessToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`)) // 200 but no tokens
	}))
	defer ts.Close()

	tObj := &TraefikOidc{
		logger:           GetSingletonNoOpLogger(),
		providerURL:      "https://issuer.example.com",
		clientID:         "cid",
		clientSecret:     "secret",
		clientAuthMethod: "client_secret_post",
		tokenURL:         ts.URL,
		tokenHTTPClient:  ts.Client(),
	}

	_, err := tObj.exchangeTokens(context.Background(), "authorization_code", "the-code", "https://issuer.example.com/cb", "")
	if err == nil {
		t.Error("token endpoint returning 200 without access_token must be an error (RFC 6749 §5.1); got success")
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("expected access_token-related error, got: %v", err)
	}
}
