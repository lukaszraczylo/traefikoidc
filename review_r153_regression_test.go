package traefikoidc

import (
	"strings"
	"testing"
	"time"
)

// R153 review-round regressions.

// TestRedactCallbackURL covers the callback-log redaction helper: the
// one-time authorization code and the state value must be redacted from
// the URL used in the callback Debug/Error log lines, while unrelated
// query values survive. Fail-on-old: the helper previously returned the
// full req.URL.String() (auth_flow.go Debug ~line 195 / Error ~line 230),
// which published the single-use code into the log pipeline.
func TestRedactCallbackURL(t *testing.T) {
	raw := "https://auth.example/callback?code=SECRETCODE123&state=coolstate&issuer=idp"
	got := redactCallbackURL(raw)

	for _, leaked := range []string{"SECRETCODE123", "coolstate"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redactCallbackURL(%q) leaked %q in %q", raw, leaked, got)
		}
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("redactCallbackURL(%q) = %q: expected redaction markers", raw, got)
	}
	if !strings.Contains(got, "issuer=idp") {
		t.Fatalf("redactCallbackURL(%q) dropped unrelated query param: %q", raw, got)
	}

	// Malformed input returned unchanged, never panics.
	if s := redactCallbackURL("%zz"); s != "%zz" {
		t.Fatalf("malformed URL should pass through unchanged, got %q", s)
	}
}

// TestCacheVerifiedToken_ExpiredNotCached covers the negative-TTL guard in
// cacheVerifiedToken. An already-expired token must not be written to the
// verified-cache under a negative TTL; a still-valid token must be
// cached. Fail-on-old: cacheVerifiedToken set the cache unconditionally
// with exp-now, so an expired token (reachable via ClockSkewToleranceFuture
// leeway) was cached as dead weight (token_manager.go ~line 256).
func TestCacheVerifiedToken_ExpiredNotCached(t *testing.T) {
	ResetUniversalCacheManagerForTesting()

	tObj := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		tokenCache:     NewTokenCache(),
		tokenBlacklist: nil,
	}

	mgr := GetUniversalCacheManager(nil)
	store := mgr.GetTokenCache()

	expired := map[string]interface{}{
		"exp": float64(time.Now().Add(-time.Minute).Unix()),
		"jti": "r153-expired",
	}
	tObj.cacheVerifiedToken("r153-bearer-expired", expired)
	if n := store.Size(); n != 0 {
		t.Fatalf("expired token must not be cached under negative TTL, cache holds %d entries", n)
	}

	valid := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"jti": "r153-valid",
	}
	tObj.cacheVerifiedToken("r153-bearer-valid", valid)
	if n := store.Size(); n == 0 {
		t.Fatal("still-valid token should be cached")
	}

	ResetUniversalCacheManagerForTesting()
}
