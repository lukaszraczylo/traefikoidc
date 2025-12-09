package servers

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil/fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOIDCServer(t *testing.T) {
	t.Run("creates server with default config", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		assert.NotNil(t, server)
		assert.NotEmpty(t, server.URL)
	})

	t.Run("creates server with custom config", func(t *testing.T) {
		config := &OIDCServerConfig{
			Issuer:          "https://custom-issuer.com",
			ScopesSupported: []string{"openid", "custom"},
		}
		server := NewOIDCServer(config)
		defer server.Close()

		assert.NotNil(t, server)
		assert.Equal(t, "https://custom-issuer.com", server.Config.Issuer)
	})
}

func TestDiscoveryEndpoint(t *testing.T) {
	server := NewOIDCServer(nil)
	defer server.Close()

	resp, err := http.Get(server.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var discovery map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	require.NoError(t, err)

	assert.Equal(t, server.URL, discovery["issuer"])
	assert.Contains(t, discovery["token_endpoint"], "/token")
	assert.Contains(t, discovery["jwks_uri"], "/jwks")
	assert.Contains(t, discovery["authorization_endpoint"], "/authorize")
}

func TestTokenEndpoint(t *testing.T) {
	t.Run("returns default token response", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		resp, err := http.PostForm(server.URL+"/token", map[string][]string{
			"grant_type": {"authorization_code"},
			"code":       {"test-code"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		assert.NotEmpty(t, tokenResp["access_token"])
		assert.NotEmpty(t, tokenResp["refresh_token"])
	})

	t.Run("returns configured error", func(t *testing.T) {
		config := DefaultConfig()
		config.TokenError = &OIDCError{
			Error:       "invalid_grant",
			Description: "The authorization code is invalid",
		}
		server := NewOIDCServer(config)
		defer server.Close()

		resp, err := http.PostForm(server.URL+"/token", map[string][]string{
			"grant_type": {"authorization_code"},
			"code":       {"test-code"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp OIDCError
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)

		assert.Equal(t, "invalid_grant", errResp.Error)
	})

	t.Run("handles refresh token grant", func(t *testing.T) {
		config := DefaultConfig()
		config.RefreshResponse = map[string]interface{}{
			"access_token": "new-access-token",
			"expires_in":   3600,
		}
		server := NewOIDCServer(config)
		defer server.Close()

		resp, err := http.PostForm(server.URL+"/token", map[string][]string{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"test-refresh-token"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		assert.Equal(t, "new-access-token", tokenResp["access_token"])
	})
}

func TestJWKSEndpoint(t *testing.T) {
	t.Run("returns empty JWKS without fixture", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		resp, err := http.Get(server.URL + "/jwks")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var jwks map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&jwks)
		require.NoError(t, err)

		assert.Contains(t, jwks, "keys")
	})

	t.Run("returns JWKS from fixture", func(t *testing.T) {
		fixture, err := fixtures.NewTokenFixture()
		require.NoError(t, err)

		config := DefaultConfig()
		config.TokenFixture = fixture
		server := NewOIDCServer(config)
		defer server.Close()

		resp, err := http.Get(server.URL + "/jwks")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var jwks map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&jwks)
		require.NoError(t, err)

		keys, ok := jwks["keys"].([]interface{})
		require.True(t, ok)
		assert.Len(t, keys, 1)
	})
}

func TestUserinfoEndpoint(t *testing.T) {
	t.Run("returns default userinfo", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		resp, err := http.Get(server.URL + "/userinfo")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var userinfo map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&userinfo)
		require.NoError(t, err)

		assert.NotEmpty(t, userinfo["sub"])
		assert.NotEmpty(t, userinfo["email"])
	})

	t.Run("returns configured userinfo", func(t *testing.T) {
		config := DefaultConfig()
		config.UserinfoResponse = map[string]interface{}{
			"sub":   "custom-sub",
			"email": "custom@example.com",
			"name":  "Custom User",
		}
		server := NewOIDCServer(config)
		defer server.Close()

		resp, err := http.Get(server.URL + "/userinfo")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var userinfo map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&userinfo)
		require.NoError(t, err)

		assert.Equal(t, "custom@example.com", userinfo["email"])
	})
}

func TestIntrospectionEndpoint(t *testing.T) {
	t.Run("returns active token", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		resp, err := http.PostForm(server.URL+"/introspect", map[string][]string{
			"token": {"test-token"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var introspection map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&introspection)
		require.NoError(t, err)

		assert.Equal(t, true, introspection["active"])
	})
}

func TestRevocationEndpoint(t *testing.T) {
	server := NewOIDCServer(nil)
	defer server.Close()

	resp, err := http.PostForm(server.URL+"/revoke", map[string][]string{
		"token": {"test-token"},
	})
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLogoutEndpoint(t *testing.T) {
	t.Run("returns OK without redirect", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Get(server.URL + "/logout")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("redirects with post_logout_redirect_uri", func(t *testing.T) {
		server := NewOIDCServer(nil)
		defer server.Close()

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Get(server.URL + "/logout?post_logout_redirect_uri=https://example.com/logged-out")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, "https://example.com/logged-out", resp.Header.Get("Location"))
	})
}

func TestRequestTracking(t *testing.T) {
	server := NewOIDCServer(nil)
	defer server.Close()

	assert.Equal(t, 0, server.GetRequestCount())

	http.Get(server.URL + "/.well-known/openid-configuration")
	assert.Equal(t, 1, server.GetRequestCount())

	http.Get(server.URL + "/jwks")
	assert.Equal(t, 2, server.GetRequestCount())

	requests := server.GetRequests()
	assert.Len(t, requests, 2)

	server.Reset()
	assert.Equal(t, 0, server.GetRequestCount())
	assert.Len(t, server.GetRequests(), 0)
}

func TestRateLimiting(t *testing.T) {
	config := RateLimitedConfig(2)
	server := NewOIDCServer(config)
	defer server.Close()

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		resp, err := http.PostForm(server.URL+"/token", map[string][]string{
			"grant_type": {"authorization_code"},
			"code":       {"test-code"},
		})
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Third request should be rate limited
	resp, err := http.PostForm(server.URL+"/token", map[string][]string{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
	})
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

func TestSlowServer(t *testing.T) {
	config := SlowServerConfig(100 * time.Millisecond)
	server := NewOIDCServer(config)
	defer server.Close()

	start := time.Now()
	resp, err := http.PostForm(server.URL+"/token", map[string][]string{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	resp.Body.Close()

	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(100))
}

func TestProviderConfigs(t *testing.T) {
	t.Run("GoogleConfig", func(t *testing.T) {
		config := GoogleConfig()
		assert.Equal(t, "https://accounts.google.com", config.Issuer)
		assert.NotContains(t, config.ScopesSupported, "offline_access")
	})

	t.Run("AzureConfig", func(t *testing.T) {
		config := AzureConfig()
		assert.Contains(t, config.Issuer, "microsoftonline.com")
		assert.Contains(t, config.ScopesSupported, "offline_access")
	})

	t.Run("Auth0Config", func(t *testing.T) {
		config := Auth0Config()
		assert.Contains(t, config.ScopesSupported, "offline_access")
	})

	t.Run("KeycloakConfig", func(t *testing.T) {
		config := KeycloakConfig()
		assert.Contains(t, config.ScopesSupported, "roles")
		assert.Contains(t, config.ScopesSupported, "groups")
	})
}

func TestTimeoutConfig(t *testing.T) {
	config := TimeoutConfig(50 * time.Millisecond)
	server := NewOIDCServer(config)
	defer server.Close()

	client := &http.Client{
		Timeout: 100 * time.Millisecond,
	}

	start := time.Now()
	resp, err := client.Get(server.URL + "/.well-known/openid-configuration")
	elapsed := time.Since(start)

	// Either timeout or empty response
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// With timeout simulation, response body may be empty
		assert.True(t, len(body) == 0 || elapsed >= 50*time.Millisecond)
	}
}
