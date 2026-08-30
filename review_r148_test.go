package traefikoidc

import (
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

func r148BaseConfig() *Config {
	c := CreateConfig()
	c.ProviderURL = "https://provider.example.com"
	c.ClientID = "test-client"
	c.ClientSecret = "test-secret"
	c.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	c.CallbackURL = "/callback"
	return c
}

// TestConfigValidates_ScopesRequireOpenID guards the R148 fix in
// settings.go Validate: scopes flow verbatim into the OIDC authorize
// request. An empty scope element (trailing comma in a Traefik label)
// and an override that drops the mandatory "openid" scope are rejected
// by strict OIDC providers at runtime (OIDC Core 3.1.2.1) — every
// login fails. Validate now rejects both at startup.
func TestConfigValidates_ScopesRequireOpenID(t *testing.T) {
	empty := r148BaseConfig()
	empty.Scopes = []string{"profile", ""}
	if err := empty.Validate(); err == nil {
		t.Fatal("empty scope element must be rejected by Validate")
	}

	overrideNoOpenID := r148BaseConfig()
	overrideNoOpenID.OverrideScopes = true
	overrideNoOpenID.Scopes = []string{"profile"}
	if err := overrideNoOpenID.Validate(); err == nil {
		t.Fatal("overrideScopes without mandatory openid scope must be rejected by Validate")
	}

	ok := r148BaseConfig()
	ok.Scopes = []string{"openid", "profile"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid scopes must pass Validate, got: %v", err)
	}
}

// TestConfigValidates_SecurityHeaderCRLF guards the R148 fix:
// SecurityHeader CORS lists and CustomHeaders are emitted verbatim into
// response headers; a CR/LF would split/corrupt the header. Validate
// now rejects CR/LF/NUL in these values.
func TestConfigValidates_SecurityHeaderCRLF(t *testing.T) {
	cors := r148BaseConfig()
	cors.SecurityHeaders = &SecurityHeadersConfig{}
	cors.SecurityHeaders.CORSAllowedHeaders = []string{"X-Auth\r\nInjected: 1"}
	if err := cors.Validate(); err == nil {
		t.Fatal("CORSAllowedHeaders entry with CR must be rejected by Validate")
	}

	custom := r148BaseConfig()
	custom.SecurityHeaders = &SecurityHeadersConfig{}
	custom.SecurityHeaders.CustomHeaders = map[string]string{"X-Custom": "a\nb"}
	if err := custom.Validate(); err == nil {
		t.Fatal("CustomHeaders value with LF must be rejected by Validate")
	}

	ok := r148BaseConfig()
	ok.SecurityHeaders = &SecurityHeadersConfig{}
	ok.SecurityHeaders.CORSAllowedHeaders = []string{"X-Auth"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("clean security headers must pass Validate, got: %v", err)
	}
}

// TestConfigValidates_HeaderName guard the R148 fix: a header Name
// with characters illegal in an HTTP field name would be written
// verbatim into every response line by Go's server, corrupting it.
func TestConfigValidates_HeaderName(t *testing.T) {
	bad := r148BaseConfig()
	bad.Headers = []TemplatedHeader{{Name: "X User Email", Value: "x@y.z"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("header name with space must be rejected by Validate")
	}

	ok := r148BaseConfig()
	ok.Headers = []TemplatedHeader{{Name: "X-User-Email", Value: "someone@example.com"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid header name must pass Validate, got: %v", err)
	}
}

// TestVerify_JTIBlacklistPiercesCache guard the R148 fix in
// verifyTokenWithOpts: the cached fast-return must still reject a token
// whose JTI has been blacklisted. A same-JTI rotated token that
// happens to be cached would otherwise keep returning "valid" until the
// cache TTL even though its JTI was revoked under a different raw
// value.
func TestVerify_JTIBlacklistPiercesCache(t *testing.T) {
	oidc := makeBearerOIDC(t, nil)
	// makeBearerOIDC leaves tokenBlacklist nil; wire an isolated one.
	oidc.tokenBlacklist = newMapCache()

	token := "aaa.bbb.ccc" // not the test-key prefix; 2 dots, len >= 10
	seedVerified(t, oidc, token, map[string]interface{}{"sub": "u", "jti": "shared-jti"})
	oidc.tokenBlacklist.Set("shared-jti", time.Now().Unix(), time.Minute)

	if err := oidc.verifyTokenWithOpts(token, verifyOpts{}); err == nil {
		t.Fatal("cached token whose JTI is blacklisted must be rejected (fast path must pierce jti)")
	}
}

// TestChunk_NoIndexZeroNoPanic guards the R148 fix in
// processChunkedToken: a sparse chunk set without index 0 previously
// nil-dereferenced chunks[0].Now it must return a clean missing-chunk
// error instead of panicking.
func TestChunk_NoIndexZeroNoPanic(t *testing.T) {
	cm := NewChunkManager(newNoOpLogger())
	chunks := map[int]*sessions.Session{
		1: {Values: map[interface{}]interface{}{"token_chunk": "part1", "token_total": 1}},
	}

	res := cm.processChunkedToken(chunks, RefreshTokenConfig)
	if res.Error == nil {
		t.Fatal("sparse chunk set missing index 0 must return an error, not a token")
	}
	if !strings.Contains(res.Error.Error(), "missing") {
		t.Fatalf("expected missing-chunk error, got: %v", res.Error)
	}
}
