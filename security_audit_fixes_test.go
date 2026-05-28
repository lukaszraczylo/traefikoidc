package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

// TestRank1_SessionCookieIsEncrypted verifies that the session cookie payload is
// AES-encrypted, not merely HMAC-signed. Regression test for the audit finding
// "session cookies signed but NOT encrypted": a single key left the stored OIDC
// tokens recoverable in plaintext from the raw cookie bytes.
func TestRank1_SessionCookieIsEncrypted(t *testing.T) {
	const secret = "a-sufficiently-long-session-encryption-key"
	authKey, encKey := deriveCookieKeys(secret)
	if len(authKey) != 64 || len(encKey) != 32 {
		t.Fatalf("expected 64-byte auth key and 32-byte enc key, got %d/%d", len(authKey), len(encKey))
	}
	if string(authKey) == string(encKey) {
		t.Fatal("authentication and encryption keys must be independent")
	}

	const marker = "SUPER-SECRET-ACCESS-TOKEN-marker-value"

	// Encode a session through the same two-key store the production code now
	// builds (see NewSessionManager).
	store := sessions.NewCookieStore(authKey, encKey)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	sess, err := store.New(req, "session")
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	sess.Values["tok"] = marker
	if err := sess.Save(req, rec); err != nil {
		t.Fatalf("session save failed: %v", err)
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}

	// The secret token must never appear in plaintext in the cookie value.
	if strings.Contains(cookie.Value, marker) {
		t.Error("marker token found in plaintext inside the session cookie value")
	}

	// A store holding only the authentication key (the previous behavior)
	// must NOT be able to read the encrypted cookie — proving the payload is
	// genuinely encrypted, not just signed.
	signedOnly := sessions.NewCookieStore(authKey)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)
	if _, derr := signedOnly.Get(req2, "session"); derr == nil {
		t.Error("encrypted cookie should not be decodable without the encryption key")
	}

	// The full two-key store round-trips correctly.
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.AddCookie(cookie)
	rt, derr := store.Get(req3, "session")
	if derr != nil {
		t.Fatalf("round-trip decode failed: %v", derr)
	}
	if got, _ := rt.Values["tok"].(string); got != marker {
		t.Errorf("round-trip mismatch: got %q want %q", got, marker)
	}
}

// TestRank2And6_InvalidConfigFailsClosed verifies that NewWithContext now calls
// Config.Validate() and fails closed on an empty or too-short session
// encryption key instead of silently substituting a public hardcoded key, and
// rejects other missing required fields. Regression test for "hardcoded default
// encryption key" + "Config.Validate() never called in production path".
func TestRank2And6_InvalidConfigFailsClosed(t *testing.T) {
	base := func() *Config {
		return &Config{
			ProviderURL:          "https://accounts.google.com",
			ClientID:             "test-client",
			ClientSecret:         "test-secret",
			CallbackURL:          "/callback",
			SessionEncryptionKey: "this-is-a-valid-session-key-32b!",
			RateLimit:            100,
		}
	}

	// Sanity: a fully valid config still constructs.
	p, err := NewWithContext(context.Background(), base(), nil, "valid")
	if err != nil {
		t.Fatalf("valid config should construct, got: %v", err)
	}
	if p != nil {
		p.Close()
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty key", func(c *Config) { c.SessionEncryptionKey = "" }},
		{"short key", func(c *Config) { c.SessionEncryptionKey = "tooshort" }},
		{"missing providerURL", func(c *Config) { c.ProviderURL = "" }},
		{"missing callbackURL", func(c *Config) { c.CallbackURL = "" }},
		{"plaintext remote providerURL", func(c *Config) { c.ProviderURL = "http://accounts.google.com" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			plugin, err := NewWithContext(context.Background(), c, nil, tc.name)
			if err == nil {
				if plugin != nil {
					plugin.Close()
				}
				t.Errorf("expected NewWithContext to reject config (%s), but it succeeded", tc.name)
			}
		})
	}
}

// TestRank3_DiscoveredEndpointSSRFGuard verifies that endpoints from the
// provider discovery document are screened against SSRF targets before use.
func TestRank3_DiscoveredEndpointSSRFGuard(t *testing.T) {
	tr := &TraefikOidc{}

	blocked := []string{
		"http://169.254.169.254/latest/meta-data/", // cloud metadata (link-local)
		"http://[fe80::1]/jwks",                    // IPv6 link-local
		"http://10.0.0.5/jwks",                     // private
		"http://192.168.1.10/jwks",                 // private
		"http://127.0.0.1/jwks",                    // loopback (allowLoopback=false)
		"ftp://example.com/jwks",                   // disallowed scheme
	}
	for _, u := range blocked {
		if err := tr.validateDiscoveredEndpoint(u, false); err == nil {
			t.Errorf("expected discovered endpoint %q to be rejected", u)
		}
	}

	allowed := []string{
		"https://accounts.google.com/o/oauth2/v3/certs",
		"https://www.googleapis.com/oauth2/v3/certs", // cross-domain JWKS must stay allowed
		"", // empty optional endpoint
	}
	for _, u := range allowed {
		if err := tr.validateDiscoveredEndpoint(u, false); err != nil {
			t.Errorf("expected discovered endpoint %q to be allowed, got %v", u, err)
		}
	}

	// Loopback is allowed only when the provider itself is loopback (dev/test).
	if err := tr.validateDiscoveredEndpoint("http://127.0.0.1:8080/jwks", true); err != nil {
		t.Errorf("loopback endpoint should be allowed when allowLoopback=true: %v", err)
	}
	// Private addresses are allowed when explicitly opted in.
	trPriv := &TraefikOidc{allowPrivateIPAddresses: true}
	if err := trPriv.validateDiscoveredEndpoint("http://10.0.0.5/jwks", false); err != nil {
		t.Errorf("private endpoint should be allowed when allowPrivateIPAddresses=true: %v", err)
	}
}

// TestRank4_IntrospectionHostPin verifies the host-equality check used to pin
// the credential-bearing introspection endpoint to the configured provider.
func TestRank4_IntrospectionHostPin(t *testing.T) {
	if !sameHost("https://kc.example.com/realms/x", "https://kc.example.com/realms/x/protocol/openid-connect/token/introspect") {
		t.Error("introspection on the same host as the provider should be accepted")
	}
	if sameHost("https://kc.example.com", "https://evil.example.net/introspect") {
		t.Error("introspection on a different host must be rejected")
	}
	if sameHost("", "https://kc.example.com") || sameHost("https://kc.example.com", "") {
		t.Error("empty URL must not be treated as a host match")
	}
}
