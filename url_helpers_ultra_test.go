package traefikoidc

import (
	"crypto/tls"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test TLS connection state for testing HTTPS detection
var testTLSState = tls.ConnectionState{
	Version:           tls.VersionTLS13,
	HandshakeComplete: true,
	ServerName:        "example.com",
}

// createMinimalMiddleware creates a minimal TraefikOidc instance for testing URL helpers
func createMinimalMiddleware() *TraefikOidc {
	logger := newNoOpLogger()
	return &TraefikOidc{
		logger:       logger,
		issuerURL:    "https://provider.example.com",
		clientID:     "test-client",
		clientSecret: "test-secret",
		authURL:      "https://provider.example.com/authorize",
		tokenURL:     "https://provider.example.com/token",
		excludedURLs: make(map[string]struct{}),
		scopes:       []string{"openid", "profile", "email"},
		enablePKCE:   false,
	}
}

// TestDetermineScheme tests scheme determination edge cases
func TestDetermineScheme(t *testing.T) {
	middleware := createMinimalMiddleware()

	t.Run("defaults to http when no headers or TLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/auth", nil)
		scheme := middleware.determineScheme(req)
		assert.Equal(t, "http", scheme)
	})

	t.Run("uses X-Forwarded-Proto when present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/auth", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		scheme := middleware.determineScheme(req)
		assert.Equal(t, "https", scheme)
	})

	t.Run("X-Forwarded-Proto takes precedence over TLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com/auth", nil)
		req.TLS = &testTLSState
		req.Header.Set("X-Forwarded-Proto", "http")
		scheme := middleware.determineScheme(req)
		assert.Equal(t, "http", scheme)
	})

	t.Run("uses TLS when present and no X-Forwarded-Proto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com/auth", nil)
		req.TLS = &testTLSState
		scheme := middleware.determineScheme(req)
		assert.Equal(t, "https", scheme)
	})
}

// TestBuildURLWithParamsErrorPaths tests error handling in buildURLWithParams
func TestBuildURLWithParamsErrorPaths(t *testing.T) {
	middleware := createMinimalMiddleware()

	t.Run("invalid issuer URL returns empty string", func(t *testing.T) {
		middleware.issuerURL = "://invalid"
		params := url.Values{}
		params.Set("test", "value")
		result := middleware.buildURLWithParams("/path", params)
		assert.Empty(t, result)
	})

	t.Run("invalid relative URL returns empty string", func(t *testing.T) {
		middleware.issuerURL = "https://provider.example.com"
		params := url.Values{}
		result := middleware.buildURLWithParams("://invalid-relative", params)
		assert.Empty(t, result)
	})

	t.Run("invalid absolute URL returns empty string", func(t *testing.T) {
		params := url.Values{}
		result := middleware.buildURLWithParams("http://[invalid-url", params)
		assert.Empty(t, result)
	})

	t.Run("dangerous host in absolute URL returns empty string", func(t *testing.T) {
		params := url.Values{}
		result := middleware.buildURLWithParams("https://localhost/callback", params)
		assert.Empty(t, result)
	})

	t.Run("successful relative URL resolution", func(t *testing.T) {
		middleware.issuerURL = "https://provider.example.com"
		params := url.Values{}
		params.Set("key", "value")
		result := middleware.buildURLWithParams("/oauth/authorize", params)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "https://provider.example.com/oauth/authorize")
		assert.Contains(t, result, "key=value")
	})

	t.Run("successful absolute URL", func(t *testing.T) {
		params := url.Values{}
		params.Set("client_id", "test")
		result := middleware.buildURLWithParams("https://api.example.com/endpoint", params)
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "https://api.example.com/endpoint")
		assert.Contains(t, result, "client_id=test")
	})
}

// TestValidateParsedURLCases tests URL validation edge cases
func TestValidateParsedURLCases(t *testing.T) {
	middleware := createMinimalMiddleware()

	t.Run("disallowed schemes rejected", func(t *testing.T) {
		invalidSchemes := []string{
			"ftp://example.com",
			"file:///etc/passwd",
			"javascript:alert(1)",
			"data:text/html,test",
		}

		for _, urlStr := range invalidSchemes {
			u, _ := url.Parse(urlStr)
			err := middleware.validateParsedURL(u)
			assert.Error(t, err, "should reject scheme: %s", urlStr)
			assert.Contains(t, err.Error(), "disallowed URL scheme")
		}
	})

	t.Run("http scheme allowed with warning", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/path")
		err := middleware.validateParsedURL(u)
		assert.NoError(t, err)
	})

	t.Run("missing host rejected", func(t *testing.T) {
		u := &url.URL{
			Scheme: "https",
			Host:   "",
			Path:   "/path",
		}
		err := middleware.validateParsedURL(u)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing host")
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		u, _ := url.Parse("https://example.com/../../etc/passwd")
		err := middleware.validateParsedURL(u)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path traversal")
	})

	t.Run("valid URLs accepted", func(t *testing.T) {
		validURLs := []string{
			"https://example.com",
			"https://example.com/path",
			"https://sub.example.com:8080/path?query=value",
		}

		for _, urlStr := range validURLs {
			u, _ := url.Parse(urlStr)
			err := middleware.validateParsedURL(u)
			assert.NoError(t, err, "should accept: %s", urlStr)
		}
	})
}

// TestValidateHostComprehensive tests comprehensive host validation
func TestValidateHostComprehensive(t *testing.T) {
	middleware := createMinimalMiddleware()

	t.Run("loopback IPs rejected", func(t *testing.T) {
		loopbacks := []string{
			"127.0.0.1",
			"127.255.255.255",
			"::1",
		}

		for _, ip := range loopbacks {
			err := middleware.validateHost(ip)
			assert.Error(t, err, "should reject loopback: %s", ip)
		}
	})

	t.Run("private IPs rejected", func(t *testing.T) {
		privateIPs := []string{
			"10.0.0.1",
			"172.16.0.1",
			"192.168.1.1",
			"fd00::1",
		}

		for _, ip := range privateIPs {
			err := middleware.validateHost(ip)
			assert.Error(t, err, "should reject private IP: %s", ip)
		}
	})

	t.Run("link-local IPs rejected", func(t *testing.T) {
		linkLocal := []string{
			"169.254.1.1",
			"fe80::1",
		}

		for _, ip := range linkLocal {
			err := middleware.validateHost(ip)
			assert.Error(t, err, "should reject link-local: %s", ip)
		}
	})

	t.Run("unspecified and multicast rejected", func(t *testing.T) {
		special := []string{
			"0.0.0.0",
			"::",
			"224.0.0.1",
			"ff02::1",
		}

		for _, ip := range special {
			err := middleware.validateHost(ip)
			assert.Error(t, err, "should reject special IP: %s", ip)
		}
	})

	t.Run("dangerous hostnames rejected", func(t *testing.T) {
		dangerous := []string{
			"localhost",
			"LOCALHOST",
			"169.254.169.254",
			"metadata.google.internal",
		}

		for _, host := range dangerous {
			err := middleware.validateHost(host)
			assert.Error(t, err, "should reject: %s", host)
		}
	})

	t.Run("invalid host format rejected", func(t *testing.T) {
		invalid := []string{
			"[::1:invalid",
		}

		for _, host := range invalid {
			err := middleware.validateHost(host)
			assert.Error(t, err, "should reject invalid format: %s", host)
		}
	})

	t.Run("hosts with ports", func(t *testing.T) {
		err := middleware.validateHost("localhost:8080")
		assert.Error(t, err)

		err = middleware.validateHost("192.168.1.1:443")
		assert.Error(t, err)

		err = middleware.validateHost("example.com:443")
		assert.NoError(t, err)
	})

	t.Run("valid public IPs accepted", func(t *testing.T) {
		publicIPs := []string{
			"8.8.8.8",
			"1.1.1.1",
			"93.184.216.34",
		}

		for _, ip := range publicIPs {
			err := middleware.validateHost(ip)
			assert.NoError(t, err, "should accept public IP: %s", ip)
		}
	})

	t.Run("valid hostnames accepted", func(t *testing.T) {
		validHosts := []string{
			"example.com",
			"sub.example.com",
			"api.service.example.com:443",
		}

		for _, host := range validHosts {
			err := middleware.validateHost(host)
			assert.NoError(t, err, "should accept: %s", host)
		}
	})
}

// TestValidateURLEdgeCasesComprehensive tests the validateURL wrapper
func TestValidateURLEdgeCasesComprehensive(t *testing.T) {
	middleware := createMinimalMiddleware()

	t.Run("empty URL rejected", func(t *testing.T) {
		err := middleware.validateURL("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty URL")
	})

	t.Run("invalid URL format rejected", func(t *testing.T) {
		err := middleware.validateURL("ht tp://invalid url")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid URL format")
	})

	t.Run("valid URLs accepted", func(t *testing.T) {
		validURLs := []string{
			"https://example.com/path",
			"https://example.com/path?key=value",
		}

		for _, urlStr := range validURLs {
			err := middleware.validateURL(urlStr)
			assert.NoError(t, err, "should accept: %s", urlStr)
		}
	})

	t.Run("URL with dangerous host rejected", func(t *testing.T) {
		err := middleware.validateURL("https://localhost/path")
		assert.Error(t, err)
		require.Contains(t, err.Error(), "invalid host")
	})
}

// TestBuildAuthURLAudienceParameter tests audience parameter handling
func TestBuildAuthURLAudienceParameter(t *testing.T) {
	t.Run("audience added when different from client_id", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.audience = "https://api.example.com"

		authURL := middleware.buildAuthURL(
			"https://app.com/callback",
			"state123",
			"nonce456",
			"",
		)

		assert.Contains(t, authURL, "audience=")
	})

	t.Run("audience not added when empty", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.audience = ""

		authURL := middleware.buildAuthURL(
			"https://app.com/callback",
			"state123",
			"nonce456",
			"",
		)

		assert.NotContains(t, authURL, "audience=")
	})

	t.Run("audience not added when equal to client_id", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.audience = middleware.clientID

		authURL := middleware.buildAuthURL(
			"https://app.com/callback",
			"state123",
			"nonce456",
			"",
		)

		assert.NotContains(t, authURL, "audience=")
	})
}

// TestBuildAuthURLPKCEParameters tests PKCE parameter handling
func TestBuildAuthURLPKCEParameters(t *testing.T) {
	t.Run("PKCE parameters added when enabled with challenge", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.enablePKCE = true

		authURL := middleware.buildAuthURL(
			"https://app.com/callback",
			"state123",
			"nonce456",
			"challenge789",
		)

		assert.Contains(t, authURL, "code_challenge=challenge789")
		assert.Contains(t, authURL, "code_challenge_method=S256")
	})

	t.Run("PKCE parameters not added when challenge empty", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.enablePKCE = true

		authURL := middleware.buildAuthURL(
			"https://app.com/callback",
			"state123",
			"nonce456",
			"", // Empty challenge
		)

		assert.NotContains(t, authURL, "code_challenge=")
	})

	t.Run("PKCE parameters not added when disabled", func(t *testing.T) {
		middleware := createMinimalMiddleware()
		middleware.enablePKCE = false

		authURL := middleware.buildAuthURL(
			"https://app.com/callback",
			"state123",
			"nonce456",
			"challenge789",
		)

		assert.NotContains(t, authURL, "code_challenge=")
	})
}
