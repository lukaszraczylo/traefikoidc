package traefikoidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildAuthURLResourceParameter verifies the RFC 8707 `resource`
// parameter is appended to the authorization URL, and that it does not
// interact with the unrelated audience/extraAuthParams handling.
func TestBuildAuthURLResourceParameter(t *testing.T) {
	t.Run("resource is added", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.resource = "https://api.example.com"

		authURL := middleware.buildAuthURL(
			"https://app.com/callback", "state123", "nonce456", "",
		)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://api.example.com"}, parsed.Query()["resource"])
	})

	t.Run("empty resource is a no-op", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		// resource left unset

		authURL := middleware.buildAuthURL(
			"https://app.com/callback", "state123", "nonce456", "",
		)

		assert.NotContains(t, authURL, "resource=")
	})

	t.Run("a resource carrying a query component is percent-encoded, not merged", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.resource = "https://api.example.com/v1?tenant=acme"

		authURL := middleware.buildAuthURL(
			"https://app.com/callback", "state123", "nonce456", "",
		)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://api.example.com/v1?tenant=acme"}, parsed.Query()["resource"])
	})

	t.Run("extraAuthParams cannot override or duplicate the resource parameter", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.resource = "https://api.example.com"
		middleware.extraAuthParams = map[string]string{
			"resource": "https://attacker.example",
		}

		authURL := middleware.buildAuthURL(
			"https://app.com/callback", "state123", "nonce456", "",
		)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://api.example.com"}, parsed.Query()["resource"])
		assert.NotContains(t, authURL, "attacker.example")
	})

	// Regression: a Resource-only config derives a validation-time audience
	// default (see TestAudienceDefaultsFromSingleResource), but that default
	// must never be sent as the non-standard `audience` request parameter —
	// manual interop testing found this made every resource-configured
	// authorization request carry both `resource=` and `audience=`, which
	// providers that give `audience` its own meaning (e.g. Ory Hydra) would
	// misinterpret.
	t.Run("a resource-derived audience default is not sent as the audience parameter", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.resource = "https://api.example.com"
		middleware.audience = "https://api.example.com" // as main.go's default would set it
		middleware.explicitAudience = ""                // Config.Audience was left unset

		authURL := middleware.buildAuthURL(
			"https://app.com/callback", "state123", "nonce456", "",
		)

		assert.NotContains(t, authURL, "audience=")
	})

	t.Run("an explicitly configured audience is still sent alongside resource", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.resource = "https://api.example.com"
		middleware.audience = "https://explicit.example.com"
		middleware.explicitAudience = "https://explicit.example.com"

		authURL := middleware.buildAuthURL(
			"https://app.com/callback", "state123", "nonce456", "",
		)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://explicit.example.com"}, parsed.Query()["audience"])
		assert.Equal(t, []string{"https://api.example.com"}, parsed.Query()["resource"])
	})
}

// newExchangeTestMiddleware builds a minimal TraefikOidc wired to server for
// exchangeTokens tests.
func newExchangeTestMiddleware(server *httptest.Server, resource string) *TraefikOidc {
	return &TraefikOidc{
		tokenURL:     server.URL + "/token",
		clientID:     "test_client",
		clientSecret: "test_secret",
		audience:     "test_client",
		resource:     resource,
		tokenHTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger:       NewLogger("debug"),
		initComplete: make(chan struct{}),
	}
}

func newResourceEchoTokenServer(t *testing.T) (*httptest.Server, *url.Values) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		values, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		captured = values

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "test_access_token",
			IDToken:      "test_id_token",
			RefreshToken: "test_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	return server, &captured
}

// TestExchangeTokensResourceParameter verifies RFC 8707 §2.2: the same
// resource indicator configured for the authorization request is also sent
// on both the authorization_code and refresh_token grants.
func TestExchangeTokensResourceParameter(t *testing.T) {
	t.Run("authorization_code grant sends the resource parameter", func(t *testing.T) {
		server, captured := newResourceEchoTokenServer(t)
		defer server.Close()

		middleware := newExchangeTestMiddleware(server, "https://api.example.com")

		_, err := middleware.exchangeTokens(context.Background(), "authorization_code", "auth-code", "https://app.com/callback", "")
		require.NoError(t, err)

		assert.Equal(t, []string{"https://api.example.com"}, (*captured)["resource"])
	})

	t.Run("refresh_token grant sends the resource parameter", func(t *testing.T) {
		server, captured := newResourceEchoTokenServer(t)
		defer server.Close()

		middleware := newExchangeTestMiddleware(server, "https://api.example.com")

		_, err := middleware.exchangeTokens(context.Background(), "refresh_token", "refresh-token-value", "", "")
		require.NoError(t, err)

		assert.Equal(t, []string{"https://api.example.com"}, (*captured)["resource"])
	})

	t.Run("no resource configured sends no resource parameter", func(t *testing.T) {
		server, captured := newResourceEchoTokenServer(t)
		defer server.Close()

		middleware := newExchangeTestMiddleware(server, "")

		_, err := middleware.exchangeTokens(context.Background(), "authorization_code", "auth-code", "https://app.com/callback", "")
		require.NoError(t, err)

		assert.NotContains(t, *captured, "resource")
	})
}

// TestConfigValidateResources exercises Config.Validate()'s RFC 8707
// resource-indicator rules.
func TestConfigValidateResources(t *testing.T) {
	baseConfig := func() *Config {
		return &Config{
			ProviderURL:          "https://provider.example.com",
			ClientID:             "test-client",
			ClientSecret:         "test-secret",
			CallbackURL:          "/callback",
			SessionEncryptionKey: "this-is-a-valid-session-key-32b!",
			RateLimit:            100,
		}
	}

	tests := []struct {
		name     string
		resource string
		audience string
		wantErr  string // substring; empty means no error expected
	}{
		{
			name:     "unset resource, no audience needed",
			resource: "",
		},
		{
			name:     "valid https resource, no audience needed",
			resource: "https://api.example.com",
		},
		{
			name:     "valid urn resource",
			resource: "urn:example:api",
		},
		{
			name:     "resource with unrelated explicit audience is allowed",
			resource: "https://api.example.com",
			audience: "https://explicit.example.com",
		},
		{
			name:     "fragment rejected",
			resource: "https://api.example.com/v1#fragment",
			wantErr:  "must not contain a fragment",
		},
		{
			name:     "relative URI rejected",
			resource: "/api/v1",
			wantErr:  "must be an absolute URI",
		},
		{
			name:     "non-loopback http rejected",
			resource: "http://api.example.com",
			wantErr:  "must be a valid HTTPS URL",
		},
		{
			name:     "loopback http accepted",
			resource: "http://127.0.0.1:8080/api",
		},
		{
			name:     "wildcard rejected",
			resource: "https://*.example.com",
			wantErr:  "must not contain wildcards",
		},
		{
			name:     "control character rejected",
			resource: "https://api.example.com/\n",
			wantErr:  "contains invalid characters",
		},
		{
			name:     "too long rejected",
			resource: "https://api.example.com/" + stringOfLength(250),
			wantErr:  "must not exceed 256 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Resource = tt.resource
			cfg.Audience = tt.audience

			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func stringOfLength(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

// TestAudienceDefaultsFromSingleResource verifies main.go's audience
// derivation: a configured resource becomes the effective validation
// audience when Audience is unset, matching what the IdP will put in the
// access token's `aud` claim.
func TestAudienceDefaultsFromSingleResource(t *testing.T) {
	baseConfig := func() *Config {
		return &Config{
			ProviderURL:          "https://provider.example.com",
			ClientID:             "test-client",
			ClientSecret:         "test-secret",
			CallbackURL:          "/callback",
			SessionEncryptionKey: "this-is-a-valid-session-key-32b!",
			RateLimit:            100,
		}
	}

	t.Run("resource, no audience: audience defaults to the resource", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Resource = "https://api.example.com"

		mw, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "test")
		require.NoError(t, err)
		t.Cleanup(func() { _ = mw.(*TraefikOidc).Close() })

		assert.Equal(t, "https://api.example.com", mw.(*TraefikOidc).audience)
		assert.Equal(t, "https://api.example.com", mw.(*TraefikOidc).resource)
		// The default must be validation-only: Config.Audience was never set,
		// so nothing should be sent as the outbound `audience` parameter.
		assert.Empty(t, mw.(*TraefikOidc).explicitAudience)
	})

	t.Run("explicit audience wins over resource", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Resource = "https://api.example.com"
		cfg.Audience = "https://explicit.example.com"

		mw, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "test")
		require.NoError(t, err)
		t.Cleanup(func() { _ = mw.(*TraefikOidc).Close() })

		assert.Equal(t, "https://explicit.example.com", mw.(*TraefikOidc).audience)
		assert.Equal(t, "https://explicit.example.com", mw.(*TraefikOidc).explicitAudience)
	})

	t.Run("no resource: audience defaults to clientID as before", func(t *testing.T) {
		cfg := baseConfig()

		mw, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "test")
		require.NoError(t, err)
		t.Cleanup(func() { _ = mw.(*TraefikOidc).Close() })

		assert.Equal(t, "test-client", mw.(*TraefikOidc).audience)
	})
}
