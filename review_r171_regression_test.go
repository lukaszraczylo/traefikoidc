package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestR171_IntrospectionEndsBasicKeform tests that the RFC 7662 introspection
// path (introtoken in token_introspection.go) authenticates the client with
// the SAME RFC 6749 §2.3.1 basic-auth encoding as the token and revocation
// endpoints (setOAuthBasicAuth): client_id and client_secret are
// form-urlencoded individually before the base64 step. Previously it used
// http.Request.SetBasicAuth (which base64s client_id:client_secret raw with
// no escaping), so for credentials containing reserved characters (":", "+",
// "@", "/", "=") the three outbound provider calls sent different wire
// credentials and an RFC 6749-strict provider rejected introspection with
// invalid_client while token exchange succeeded.
func TestR171_IntrospectionUsesOAuthBasicAuthNotRawSetBasicAuth(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// active=false keeps this free of introspection-cache state.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": false, "token_type": "Bearer"})
	}))
	defer server.Close()

	const (
		clientID     = "weird:id+1"
		clientSecret = "p@ss/word=&" //nolint:gosec // test fixture
	)

	oidc := &TraefikOidc{
		clientID:         clientID,
		clientSecret:     clientSecret,
		clientAuthMethod: "client_secret_basic",
		httpClient:       server.Client(),
		logger:           GetSingletonNoOpLogger(),
	}
	oidc.introspectionURL = server.URL
	oidc.tokenURL = "https://idp.example.com/token"

	_, err := oidc.introspectToken("opaque-token")
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(capturedAuth, "Basic "), "got %q", capturedAuth)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(capturedAuth, "Basic "))
	require.NoError(t, err)

	wantUser := url.QueryEscape(clientID)
	wantPass := url.QueryEscape(clientSecret)
	assert.Equal(t, wantUser+":"+wantPass, string(raw),
		"introspection must form-urlencode client_id and client_secret before base64, matching the token/revocation endpoints")
}
