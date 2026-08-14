package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestApplyBypassUserHeaders_ClearsForgedIdentityHeaders regresses the SSE/
// WebSocket bypass path (applyBypassUserHeaders) letting client-forged
// identity headers through to the backend. Unlike forwardAuthorized, the
// bypass path previously set only X-Forwarded-User / X-Auth-Request-User
// without clearing the other owned identity headers first, so a request
// carrying e.g. "X-User-Groups: admin" reached the backend unmodified —
// a spoofable trust boundary for backends that authorize on those headers.
func TestApplyBypassUserHeaders_ClearsForgedIdentityHeaders(t *testing.T) {
	sm := createTestSessionManager(t)

	base := httptest.NewRequest(http.MethodGet, "/protected", nil)
	baseRec := httptest.NewRecorder()

	session, err := sm.GetSession(base)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("SetAuthenticated: %v", err)
	}
	session.SetUserIdentifier("user@company.com")
	if err := session.Save(base, baseRec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range baseRec.Result().Cookies() {
		req.AddCookie(c)
	}

	// Client forges identity headers that this path does not compute.
	req.Header.Set("X-User-Groups", "admin")
	req.Header.Set("X-User-Roles", "superuser")
	req.Header.Set("X-Auth-Request-Redirect", "/evil")
	req.Header.Set("X-Auth-Request-Token", "forged-token")
	req.Header.Set("X-Forwarded-User", "forged")
	req.Header.Set("X-Auth-Request-User", "forged")

	oidc := &TraefikOidc{
		sessionManager: sm,
		logger:         NewLogger("debug"),
	}

	if ok, _ := oidc.applyBypassUserHeaders(req, "test"); !ok {
		t.Fatalf("applyBypassUserHeaders returned false; bypass should be honored")
	}

	// The authoritative value wins; every other owned identity header must be
	// cleared so no forged value reaches the backend.
	if v := req.Header.Get("X-Forwarded-User"); v != "user@company.com" {
		t.Fatalf("X-Forwarded-User = %q, want authoritative %q", v, "user@company.com")
	}
	for _, h := range []string{
		"X-User-Groups",
		"X-User-Roles",
		"X-Auth-Request-Redirect",
		"X-Auth-Request-Token",
	} {
		if v := req.Header.Get(h); v != "" {
			t.Fatalf("%s survived the bypass with forged value %q; must be cleared", h, v)
		}
	}
}

// TestApplyBypassUserHeaders_UnsafeIdentifierClearsForgedValue regresses the
// sanitize-failure early return in applyBypassUserHeaders previously
// leaving an inbound forged X-Forwarded-User / X-Auth-Request-User
// intact (it returned without touching headers). Clear-before-sanitize now
// guarantees forged values are gone even when the authoritative one is
// dropped as unsafe.
func TestApplyBypassUserHeaders_UnsafeIdentifierClearsForgedValue(t *testing.T) {
	sm := createTestSessionManager(t)

	base := httptest.NewRequest(http.MethodGet, "/protected", nil)
	baseRec := httptest.NewRecorder()

	session, err := sm.GetSession(base)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("SetAuthenticated: %v", err)
	}
	session.SetUserIdentifier("user\nX-Injected: yes") // unsafe -> dropped
	if err := session.Save(base, baseRec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range baseRec.Result().Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-Forwarded-User", "forged")
	req.Header.Set("X-Auth-Request-User", "forged")

	oidc := &TraefikOidc{
		sessionManager: sm,
		logger:         NewLogger("debug"),
	}

	if ok, _ := oidc.applyBypassUserHeaders(req, "test"); !ok {
		t.Fatalf("applyBypassUserHeaders returned false; bypass should be honored")
	}
	if v := req.Header.Get("X-Forwarded-User"); v != "" {
		t.Fatalf("X-Forwarded-User = %q, want empty (authoritative dropped, forged cleared)", v)
	}
	if v := req.Header.Get("X-Auth-Request-User"); v != "" {
		t.Fatalf("X-Auth-Request-User = %q, want empty (authoritative dropped, forged cleared)", v)
	}
}

// TestEmailIdentityPermitted_NumericUnverifiedRejected regresses that an
// email explicitly marked unverified via a numeric email_verified claim
// (0, as emitted by some IdPs) is rejected from an email/domain
// allowlist. emailVerifiedTrue previously handled only bool/string, so a
// numeric 0 was treated as "claim absent" and the unverified email was
// permitted.
func TestEmailIdentityPermitted_NumericUnverifiedRejected(t *testing.T) {
	for name, claims := range map[string]map[string]interface{}{
		"numeric-zero":     {"email_verified": float64(0)},
		"json-number-zero": {"email_verified": json.Number("0")},
		"string-zero":      {"email_verified": "0"},
		"bool-false":       {"email_verified": false},
	} {
		if emailIdentityPermitted("user@example.com", claims) {
			t.Fatalf("case %q: unverified email must be rejected from the allowlist", name)
		}
	}

	for name, claims := range map[string]map[string]interface{}{
		"numeric-one": {"email_verified": float64(1)},
		"string-true": {"email_verified": "true"},
		"bool-true":   {"email_verified": true},
		"absent":      {},
	} {
		if !emailIdentityPermitted("user@example.com", claims) {
			t.Fatalf("case %q: verified/absent email must be permitted", name)
		}
	}
}

// TestForceJWKSRefresh_FailedFetchDoesNotSetCooldown regresses that a
// failed live JWKS refresh no longer consumes the per-URL cooldown
// window. Recording the cooldown before the fetch meant a transient
// 5xx/network blip (during a key rotation) routed every new-kid request
// to the stale cached keyset for the next jwksForceRefreshCooldown,
// producing "no matching public key" 401s with no upstream retry.
func TestForceJWKSRefresh_FailedFetchDoesNotSetCooldown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &JWKCache{
		cache:            NewUniversalCache(UniversalCacheConfig{Type: CacheTypeJWK}),
		inflightFetches:  sync.Map{},
		lastForceRefresh: make(map[string]time.Time),
	}

	if _, _, err := c.forceJWKSRefresh(context.Background(), srv.URL, srv.Client()); err == nil {
		t.Fatal("expected error from 500 JWKS response")
	}

	c.forceMu.Lock()
	_, recorded := c.lastForceRefresh[srv.URL]
	c.forceMu.Unlock()
	if recorded {
		t.Fatalf("cooldown recorded after FAILED fetch; next new-kid request will be served the stale keyset")
	}
}
