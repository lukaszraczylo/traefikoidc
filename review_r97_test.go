package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// R97 regression (Session): the refresh token's issued_at (used by the
// maxRefreshTokenAge staleness heuristic) must survive a combined-cookie
// save/load round-trip. Previously combined storage dropped it, so after
// reload GetRefreshTokenIssuedAt() returned zero and the heuristic was
// silently disabled.
func TestCombinedRoundTripPreservesRefreshIssuedAt(t *testing.T) {
	sm := createTestSessionManager(t)

	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	s, err := sm.GetSession(req0)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.useCombinedStorage = true // exercise the combined (not legacy) path
	s.SetRefreshToken("test-refresh-token-123")
	issuedAt := s.GetRefreshTokenIssuedAt()
	if issuedAt.IsZero() {
		t.Fatalf("precondition: refresh token should have a non-zero issued_at")
	}

	rec := httptest.NewRecorder()
	if err := s.Save(req0, rec); err != nil {
		t.Fatalf("save combined session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	s2, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	defer s2.returnToPoolSafely()

	if got := s2.GetRefreshTokenIssuedAt(); got.Unix() != issuedAt.Unix() {
		t.Fatalf("refresh issued_at lost after combined round-trip: want %d, got %d", issuedAt.Unix(), got.Unix())
	}
	if s2.GetRefreshToken() != "test-refresh-token-123" {
		t.Fatalf("refresh token value not preserved in combined round-trip")
	}
}

// R97 regression (Session): when the combined-cookie payload is too
// large (>10 chunks), saveCombined must fall back to the legacy
// per-token chunk format (which supports ~100KB) instead of returning
// an error and dropping the session. Previously a large (incompressible)
// refresh token made Save error and forced the user to re-authenticate.
func TestSaveCombined_OverflowFallsBackToLegacy(t *testing.T) {
	sm := createTestSessionManager(t)

	// A ~17KB random JWT payload → ~23KB token: under SetRefreshToken's 50KB
	// cap (so it is stored) and under the JWT read guard (payload ≤ 40KB,
	// sig ≤ 2KB, so legacy can read it back), but incompressible so the
	// combined payload (14KB limit) overflows maxCombinedChunks. Old code
	// errored here and dropped the session; new code falls back to legacy.
	payload := make([]byte, 17*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	bigToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123")) // 26-char sig (>=10 required)
	if len(bigToken) > 50*1024 {
		t.Fatalf("precondition: token must be under the 50KB SetRefreshToken cap, got %d", len(bigToken))
	}

	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	s, err := sm.GetSession(req0)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.useCombinedStorage = true // force the combined path
	s.SetRefreshToken(bigToken)
	if s.GetRefreshToken() != bigToken {
		t.Fatalf("precondition: SetRefreshToken must have stored the large token")
	}

	rec := httptest.NewRecorder()
	if err := s.Save(req0, rec); err != nil {
		t.Fatalf("Save with oversized combined payload must fall back to legacy, got error: %v", err)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatalf("Save should still persist cookies (legacy fallback), got none")
	}
}

// R97 regression (Discovery): name-based discovery endpoints (localhost,
// cloud metadata hostnames, internal hostnames) must be SSRF-guarded just
// like IP-literal endpoints. Previously validateDiscoveredEndpoint only
// checked net.ParseIP-literal hosts, so a discovery doc returning e.g.
// metadata.google.internal or localhost bypassed the SSRF defense.
func TestValidateDiscoveredEndpoint_RejectsDangerousHostnames(t *testing.T) {
	oidc := &TraefikOidc{}

	bad := []string{
		"https://metadata.google.internal/jwks",
		"http://localhost:3000/jwks",
	}
	for _, url := range bad {
		if err := oidc.validateDiscoveredEndpoint(url, false); err == nil {
			t.Errorf("expected SSRF rejection for %q, got nil", url)
		}
	}

	// A normal public hostname must still be accepted.
	if err := oidc.validateDiscoveredEndpoint("https://login.example.com/oauth2/token", false); err != nil {
		t.Fatalf("expected public hostname to be accepted, got %v", err)
	}
}
