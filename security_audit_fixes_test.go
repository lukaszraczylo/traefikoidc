package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lukaszraczylo/traefikoidc/internal/utils"
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

// TestRank5_OpenRedirectNeutralized verifies the helper the callback now applies
// to the stored incoming path forces a host-relative redirect target.
func TestRank5_OpenRedirectNeutralized(t *testing.T) {
	cases := map[string]string{
		"//evil.com/x": "/evil.com/x",
		`/\evil.com`:   "/evil.com",
		"/legit/path":  "/legit/path",
	}
	for in, want := range cases {
		got := normalizeLogoutPath(in)
		if got != want {
			t.Errorf("normalizeLogoutPath(%q) = %q, want %q", in, got, want)
		}
		if strings.HasPrefix(got, "//") || strings.HasPrefix(got, `/\`) {
			t.Errorf("normalizeLogoutPath(%q) = %q is still protocol-relative", in, got)
		}
	}
}

// TestRank14_ExcludedURLSegmentBoundary verifies excluded-URL matching is
// anchored at path-segment boundaries and cannot be widened into a bypass.
func TestRank14_ExcludedURLSegmentBoundary(t *testing.T) {
	if !pathExcluded("/public", "/public") {
		t.Error("exact match should be excluded")
	}
	if !pathExcluded("/public/page", "/public") {
		t.Error("sub-path should be excluded")
	}
	if pathExcluded("/publicsecret", "/public") {
		t.Error("/publicsecret must NOT be excluded by /public")
	}
	if pathExcluded("/public-admin", "/public") {
		t.Error("/public-admin must NOT be excluded by /public")
	}
	if !pathExcluded("/health", "/health/") {
		t.Error("trailing-slash config should still match the exact path")
	}
	if pathExcluded("/anything", "/") {
		t.Error("root exclusion must not match arbitrary paths")
	}
	if !pathExcluded("/", "/") {
		t.Error("root exclusion should match the root path")
	}
}

// TestRank15_ForwardedHostSanitized verifies a crafted X-Forwarded-Host cannot
// inject CRLF, smuggle a second host, or otherwise poison the derived host.
func TestRank15_ForwardedHostSanitized(t *testing.T) {
	mk := func(xfh string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://real.example.com/x", nil)
		r.Host = "real.example.com"
		if xfh != "" {
			r.Header.Set("X-Forwarded-Host", xfh)
		}
		return r
	}
	if got := utils.DetermineHost(mk("ext.example.com")); got != "ext.example.com" {
		t.Errorf("clean X-Forwarded-Host should be honored, got %q", got)
	}
	if got := utils.DetermineHost(mk("a.example.com, evil.com")); got != "a.example.com" {
		t.Errorf("multi-value X-Forwarded-Host should use first host only, got %q", got)
	}
	for _, bad := range []string{"evil.com\r\nSet-Cookie: x=1", "evil.com /x", "   "} {
		if got := utils.DetermineHost(mk(bad)); got != "real.example.com" {
			t.Errorf("malformed X-Forwarded-Host %q should fall back to req.Host, got %q", bad, got)
		}
	}
}

// TestRank11_TransportPoolTLSIsolationAtLimit verifies that, once the client
// limit is reached, the transport pool reuses an existing transport only when
// its TLS settings match the caller's, and never hands back a transport built
// with different TLS trust settings.
func TestRank11_TransportPoolTLSIsolationAtLimit(t *testing.T) {
	pool := &SharedTransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	strict := DefaultHTTPClientConfig() // InsecureSkipVerify = false
	t1 := pool.GetOrCreateTransport(strict)
	if t1 == nil {
		t.Fatal("expected a transport for the strict config")
	}

	// Saturate the client limit so subsequent calls hit the fallback path.
	atomic.StoreInt32(&pool.clientCount, pool.maxClients)

	// Same TLS settings, different (non-TLS) connection limit: safe to reuse.
	sameTLS := DefaultHTTPClientConfig()
	sameTLS.MaxConnsPerHost = 99
	if got := pool.GetOrCreateTransport(sameTLS); got != t1 {
		t.Error("at the limit a TLS-compatible config should reuse the existing transport")
	}

	// Different TLS settings (InsecureSkipVerify): must NOT reuse the strict
	// transport — returning nil lets the caller fall back to a verifying default.
	insecure := DefaultHTTPClientConfig()
	insecure.InsecureSkipVerify = true
	if got := pool.GetOrCreateTransport(insecure); got == t1 {
		t.Error("at the limit a config with different TLS settings must not reuse the strict transport")
	}
}

// TestRank9_RedisFingerprint verifies divergent explicit Redis backends produce
// distinct fingerprints (used to warn about ignored cache config), while an
// absent or disabled Redis yields the empty (no-warning) fingerprint.
func TestRank9_RedisFingerprint(t *testing.T) {
	if redisFingerprint(nil) != "" {
		t.Error("nil config should yield an empty fingerprint")
	}
	if redisFingerprint(&Config{}) != "" {
		t.Error("config without Redis should yield an empty fingerprint")
	}
	if redisFingerprint(&Config{Redis: &RedisConfig{Enabled: false, Address: "a:6379"}}) != "" {
		t.Error("disabled Redis should yield an empty fingerprint")
	}
	a := redisFingerprint(&Config{Redis: &RedisConfig{Enabled: true, Address: "a:6379", KeyPrefix: "p"}})
	b := redisFingerprint(&Config{Redis: &RedisConfig{Enabled: true, Address: "b:6379", KeyPrefix: "p"}})
	if a == "" || a == b {
		t.Errorf("distinct enabled backends must produce distinct non-empty fingerprints (%q vs %q)", a, b)
	}
}

// TestRank10_TokenTypeCacheKeyNoCollision verifies that two different tokens
// sharing the same 32-character JWT header prefix are classified independently.
// The previous 32-char cache key would have collided and mis-classified them.
func TestRank10_TokenTypeCacheKeyNoCollision(t *testing.T) {
	tr := &TraefikOidc{
		tokenTypeCache:         NewCache(),
		suppressDiagnosticLogs: true,
		clientID:               "client",
	}
	// A header prefix longer than 32 chars, shared by both tokens.
	prefix := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ"
	idJWT := &JWT{Header: map[string]interface{}{}, Claims: map[string]interface{}{"nonce": "n"}}
	accessJWT := &JWT{Header: map[string]interface{}{"typ": "at+jwt"}, Claims: map[string]interface{}{}}

	if !tr.detectTokenType(idJWT, prefix+".id.sig") {
		t.Error("token with a nonce claim should be detected as an ID token")
	}
	if tr.detectTokenType(accessJWT, prefix+".access.sig") {
		t.Error("access token (typ=at+jwt) must not be mis-classified as ID despite the shared 32-char prefix")
	}
}

// TestRank12_LiveInstanceCounter verifies the process-global instance counter
// that gates teardown of shared singleton tasks.
func TestRank12_LiveInstanceCounter(t *testing.T) {
	start := atomic.LoadInt32(&liveInstanceCount)
	registerLiveInstance()
	registerLiveInstance()
	if got := atomic.LoadInt32(&liveInstanceCount); got != start+2 {
		t.Fatalf("expected %d live instances, got %d", start+2, got)
	}
	if rem := unregisterLiveInstance(); rem != start+1 {
		t.Errorf("expected %d remaining, got %d", start+1, rem)
	}
	if rem := unregisterLiveInstance(); rem != start {
		t.Errorf("expected %d remaining, got %d", start, rem)
	}
}

// TestRank13_CookieMaxAgeMatchesSessionLifetime verifies the cookie store's
// MaxAge (which bounds both the cookie Max-Age and the codec's cryptographic
// timestamp validity) is bound to the configured session lifetime rather than
// gorilla's 30-day default.
func TestRank13_CookieMaxAgeMatchesSessionLifetime(t *testing.T) {
	maxAge := 2 * time.Hour
	sm, err := NewSessionManager(strings.Repeat("k", 40), false, "", "", maxAge, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}
	defer sm.cancel()

	cs, ok := sm.store.(*sessions.CookieStore)
	if !ok {
		t.Fatal("session store is not a *sessions.CookieStore")
	}
	if got := cs.Options.MaxAge; got != int(maxAge.Seconds()) {
		t.Errorf("cookie store MaxAge = %d, want %d (bound to sessionMaxAge)", got, int(maxAge.Seconds()))
	}
}

// TestRank33And34_HeaderSanitizationDistinction verifies the two header sinks
// use the right strictness: free-form templated header VALUES (rank 34) permit
// , ; = (e.g. an opaque "Bearer <token>" or an LDAP-DN claim) but reject CR/LF,
// bidi, and over-length; claim values joined into delimited/identifier headers
// (rank 33) additionally reject , ; =.
func TestRank33And34_HeaderSanitizationDistinction(t *testing.T) {
	// Rank 34 — free-form header value.
	if headerValueReason("Bearer abc=def==", 8192) != "" {
		t.Error("'=' must be allowed in a free-form header value (opaque bearer token)")
	}
	if headerValueReason("cn=user,ou=eng;dc=x", 8192) != "" {
		t.Error("',;=' must be allowed in a free-form header value (e.g. an LDAP DN claim)")
	}
	if headerValueReason("evil"+string(rune(13))+string(rune(10))+"Injected: 1", 8192) == "" {
		t.Error("CR/LF must be rejected in a header value (injection)")
	}
	if headerValueReason("toolong", 3) == "" {
		t.Error("over-length value must be rejected")
	}

	// Rank 33 — claim value bound for a delimited/identifier header.
	if _, ok := sanitizeHeaderClaimValue("admins,superadmins", 256); ok {
		t.Error("a comma must be rejected in a value joined into a comma-delimited header")
	}
	if _, ok := sanitizeHeaderClaimValue("normal-user@example.com", 256); !ok {
		t.Error("a clean identifier must pass claim sanitization")
	}
	if _, ok := sanitizeHeaderClaimValue("evil"+string(rune(13))+string(rune(10))+"X: 1", 256); ok {
		t.Error("CR/LF must be rejected in a claim value")
	}
}
