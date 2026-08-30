package traefikoidc

// R133 regressions.
//
// F1 — cacheVerifiedToken must not re-populate the verified-token cache
// with a token (or jti) that a concurrent RevokeToken has blacklisted,
// otherwise a revoked token can serve a positive verification verdict
// until exp (the cache was only guarded by check-order at the top of
// verifyTokenWithOpts).
//
// F2 — validateTokenExpiryRS is the final authenticated gate; it must
// reject a blacklisted-but-still-cached token independently rather than
// relying on every caller happening to call verifyToken first.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

func TestCacheVerifiedToken_DoesNotReAddRevokedToken(t *testing.T) {
	blacklist := NewCache()
	token := "R133-revoked-token-aaaa-zzzz"
	blacklist.Set(token, true, time.Hour)

	oidc := &TraefikOidc{
		tokenBlacklist: blacklist,
		tokenCache:     NewTokenCache(),
		logger:         NewLogger("debug"),
	}

	claims := map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}
	oidc.cacheVerifiedToken(token, claims)

	if _, found := oidc.tokenCache.Get(token); found {
		t.Fatalf("cacheVerifiedToken re-added a blacklisted token; expected no cache entry")
	}
}

func TestCacheVerifiedToken_DoesNotReAddRevokedJTI(t *testing.T) {
	blacklist := NewCache()
	token := "R133-revoked-jti-token-aaaa-zzzz"
	jti := "R133-revoked-jti-0001"
	blacklist.Set(jti, true, time.Hour) // RevokeToken marks by jti too

	oidc := &TraefikOidc{
		tokenBlacklist: blacklist,
		tokenCache:     NewTokenCache(),
		logger:         NewLogger("debug"),
	}

	claims := map[string]interface{}{
		"jti": jti,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	oidc.cacheVerifiedToken(token, claims)

	if _, found := oidc.tokenCache.Get(token); found {
		t.Fatalf("cacheVerifiedToken re-added a token whose jti is blacklisted; expected no cache entry")
	}
}

func TestValidateTokenExpiryRS_BlacklistedToken_WithRefresh(t *testing.T) {
	blacklist := NewCache()
	token := "R133-blacklisted-exp-future-aaaa"
	blacklist.Set(token, true, time.Hour)

	oidc := &TraefikOidc{
		tokenBlacklist: blacklist,
		tokenCache:     NewTokenCache(),
		logger:         NewLogger("debug"),
	}
	// Seed the verified-cache with UNEXPIRED claims so the pre-fix code,
	// which read only the cache, would report authenticated=true.
	oidc.tokenCache.Set(token, map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}, time.Hour)

	rs := &requestState{refreshToken: "refresh-123"}
	auth, needsRefresh, expired := oidc.validateTokenExpiryRS(rs, token)

	if auth || !needsRefresh || expired {
		t.Fatalf("blacklisted-but-cached token must request refresh, got (auth=%v, needsRefresh=%v, expired=%v)", auth, needsRefresh, expired)
	}
}

func TestValidateTokenExpiryRS_BlacklistedToken_NoRefresh(t *testing.T) {
	blacklist := NewCache()
	token := "R133-blacklisted-no-refresh-aaaa"
	blacklist.Set(token, true, time.Hour)

	oidc := &TraefikOidc{
		tokenBlacklist: blacklist,
		tokenCache:     NewTokenCache(),
		logger:         NewLogger("debug"),
	}
	oidc.tokenCache.Set(token, map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}, time.Hour)

	rs := &requestState{} // no refresh token
	auth, needsRefresh, expired := oidc.validateTokenExpiryRS(rs, token)

	if auth || needsRefresh || !expired {
		t.Fatalf("blacklisted-but-cached token without refresh must force re-auth, got (auth=%v, needsRefresh=%v, expired=%v)", auth, needsRefresh, expired)
	}
}

// TestExpireLegacyCookies_RefreshChunkExpiresWhenAccessSingle verifies R133 P2-A:
// legacy refresh/id chunk cookies must be expired even when the access token is
// a single (un-chunked) cookie. Previously the shared access-driven loop
// broke all three series at the first absent access chunk, so refresh legacy
// chunk cookies were never expired during combined migration.
func TestExpireLegacyCookies_RefreshChunkExpiresWhenAccessSingle(t *testing.T) {
	sm := createTestSessionManager(t)

	// Craft ONE legacy refresh chunk cookie at index 0; NO access chunk cookie.
	seedReq := httptest.NewRequest("GET", "/", nil)
	seedRw := httptest.NewRecorder()
	refreshChunk0 := fmt.Sprintf("%s_0", sm.refreshTokenCookieName())
	rs, err := sm.store.Get(seedReq, refreshChunk0)
	if err != nil {
		t.Fatalf("store.Get refresh chunk: %v", err)
	}
	rs.Values["d"] = "some-chunk-data"
	rs.Options = &sessions.Options{Path: "/", MaxAge: 3600}
	if err := rs.Save(seedReq, seedRw); err != nil {
		t.Fatalf("save legacy refresh chunk: %v", err)
	}
	chunkVal := ""
	for _, c := range seedRw.Result().Cookies() {
		if c.Name == refreshChunk0 {
			chunkVal = c.Value
		}
	}
	if chunkVal == "" {
		t.Fatalf("failed to craft legacy refresh chunk cookie %s", refreshChunk0)
	}

	// A FRESH request carrying only that cookie (the gorilla per-request
	// registry must treat it as an existing, non-new session).
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: refreshChunk0, Value: chunkVal, Path: "/"})

	sd, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	rw := httptest.NewRecorder()
	sd.expireLegacyCookies(req, rw, &sessions.Options{Path: "/", MaxAge: 86400})

	var refreshExpired bool
	for _, c := range rw.Result().Cookies() {
		if c.Name == refreshChunk0 && c.MaxAge < 0 {
			refreshExpired = true
		}
	}
	if !refreshExpired {
		t.Fatalf("legacy refresh chunk %s was not expired when access is a single (un-chunked) cookie", refreshChunk0)
	}
}
