package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// R155 review-round regressions.

// TestR155_ServeHTTP_PanicAfterCommitKeepsBodyIntact guards the
// middleware panic-recovery fix (middleware.go). The deferred recover at
// the top of ServeHTTP used to WriteHeader(500) + Write("Internal
// Server Error") unconditionally. WriteHeader after commit is an
// idempotent no-op, but the Write appends to an already-emitted valid
// body - so a panic in the downstream handler after it had written a
// 200 + payload corrupted the response. The fix only writes the 500
// when nothing was committed yet.
// Fail-on-old: the committed 200 body gains a trailing
// "Internal Server Error", making the assertion below fail.
func TestR155_ServeHTTP_PanicAfterCommitKeepsBodyIntact(t *testing.T) {
	var nextCalled bool
	oidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("VALID PAYLOAD"))
			panic("boom-after-commit")
		}),
		logger:                       NewLogger("debug"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
		excludedURLs:                 map[string]struct{}{"/panic-excluded": {}},
		securityHeadersApplier: func(rw http.ResponseWriter, req *http.Request) {
		},
	}
	close(oidc.initComplete)

	req := httptest.NewRequest("GET", "/panic-excluded", nil)
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	if !nextCalled {
		t.Fatal("next handler was not reached")
	}
	if got := rw.Body.String(); got != "VALID PAYLOAD" {
		t.Errorf("recover must not append to a committed 200 body, got %q", got)
	}
	if rw.Code != http.StatusOK {
		t.Errorf("committed response must keep its status, got %d", rw.Code)
	}
	if strings.Contains(rw.Body.String(), "Internal Server Error") {
		t.Errorf("committed body was corrupted by the panic handler: %q", rw.Body.String())
	}
}

// TestR155_ScopeFilter_NoSupportedReturnsCopy guards the scope_filter
// aliasing fix. FilterSupportedScopes returned the caller's requested
// slice directly when the provider declared no supported scopes, so any
// later append/mutation on the returned slice shared (and mutated) the
// caller's backing array. The fix returns a copy.
// Fail-on-old: mutating result[0] also rewrites requested[0].
func TestR155_ScopeFilter_NoSupportedReturnsCopy(t *testing.T) {
	filter := NewScopeFilter(&mockScopeFilterLogger{})
	requested := []string{"openid", "profile"}
	result := filter.FilterSupportedScopes(requested, []string{}, "https://provider.example.com")

	if len(result) != len(requested) {
		t.Fatalf("expected all requested scopes, got %v", result)
	}
	result[0] = "MUTATED"
	if requested[0] != "openid" {
		t.Errorf("returned slice aliases the caller's slice: mutating result rewrote requested to %q", requested[0])
	}
}

// validInflatedIDToken returns a structurally-valid JWT whose encoded
// length is > headerTemplateMaxLen (8192): a proper header, a JSON
// payload with an exp claim plus a large random (non-repeating) claim,
// and a random signature. It must survive the ChunkManager's strict ID
// validation so SetIDToken/GetIDToken round-trip it unchanged.
func validInflatedIDToken(t *testing.T, fieldBytes int) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	big := make([]byte, fieldBytes)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	claims := map[string]interface{}{
		"iss": "https://provider.example.com",
		"sub": "user@example.com",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
		"big": base64.RawURLEncoding.EncodeToString(big),
	}
	pj, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(pj)
	sg := make([]byte, 256)
	if _, err := rand.Read(sg); err != nil {
		t.Fatal(err)
	}
	sig := base64.RawURLEncoding.EncodeToString(sg)
	return hdr + "." + payload + "." + sig
}

// TestR155_XAuthRequestToken_CappedAtHeaderBudget guards the
// X-Auth-Request-Token length cap (middleware.go). The header set the
// raw ID token with no bound, unlike every other header on the request,
// letting a large token push the request past 431 limits. The fix caps
// it at headerTemplateMaxLen (8192) like rendered template values.
// Fail-on-old: the full (uncapped) ID token is set, so the header is
// longer than 8192.
func TestR155_XAuthRequestToken_CappedAtHeaderBudget(t *testing.T) {
	oidc := newR154TestPlugin(t)
	// Ensure claim extraction returns a parseable map despite the large
	// synthetic token, so the roles/header pipeline proceeds.
	oidc.extractClaimsFunc = func(string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "user@example.com"}, nil
	}

	full := validInflatedIDToken(t, 9000)
	if len(full) <= headerTemplateMaxLen {
		t.Fatalf("setup: expected an ID token larger than %d, got %d", headerTemplateMaxLen, len(full))
	}

	var captured http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	oidc.next = next

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	session, err := oidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	session.SetUserIdentifier("user@example.com")
	session.SetAuthenticated(true)
	session.SetIDToken(full)
	if got := session.GetIDToken(); got != full {
		t.Fatalf("setup: ID token did not round-trip (len %d, want %d)", len(got), len(full))
	}

	oidc.processAuthorizedRequest(httptest.NewRecorder(), req, session, "https://example.com/callback")

	h := captured.Get("X-Auth-Request-Token")
	if len(h) != headerTemplateMaxLen {
		t.Errorf("X-Auth-Request-Token must be capped at headerTemplateMaxLen, got len %d", len(h))
	}
	if !strings.HasPrefix(full, h) {
		t.Errorf("capped header must be a prefix of the ID token")
	}
}
