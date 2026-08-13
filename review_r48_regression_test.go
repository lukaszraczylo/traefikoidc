package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestApplyBypassUserHeaders_SanitizesIdentifier is a regression test for the
// auth-bypass header path (applyBypassUserHeaders). The claim-derived user
// identifier is injected into X-Forwarded-User / X-Auth-Request-User without
// sanitization, unlike forwardAuthorized which uses sanitizeHeaderClaimValue.
// An IdP-controlled identifier containing CRLF (or a delimiter) would
// otherwise inject or confuse downstream header parsing. Now the bypass path
// sanitizes the identifier and drops the header on failure.
func TestApplyBypassUserHeaders_SanitizesIdentifier(t *testing.T) {
	sm := createTestSessionManager(t)

	base := httptest.NewRequest(http.MethodGet, "/protected", nil)
	baseRec := httptest.NewRecorder()

	// Build an authenticated session whose user identifier contains CRLF.
	session, err := sm.GetSession(base)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("SetAuthenticated: %v", err)
	}
	session.SetUserIdentifier("user\nX-Injected: yes")
	if err := session.Save(base, baseRec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range baseRec.Result().Cookies() {
		req.AddCookie(c)
	}

	oidc := &TraefikOidc{
		sessionManager: sm,
		logger:         NewLogger("debug"),
	}

	if ok := oidc.applyBypassUserHeaders(req, "test"); !ok {
		t.Fatalf("applyBypassUserHeaders returned false; bypass should be honored")
	}
	if v := req.Header.Get("X-Forwarded-User"); v != "" {
		t.Fatalf("X-Forwarded-User = %q, want empty (unsafe identifier dropped)", v)
	}
	if v := req.Header.Get("X-Auth-Request-User"); v != "" {
		t.Fatalf("X-Auth-Request-User = %q, want empty (unsafe identifier dropped)", v)
	}
}

// TestApplyBypassUserHeaders_KeepsCleanIdentifier ensures a normal identifier
// still flows through, and is trimmed/sanitized.
func TestApplyBypassUserHeaders_KeepsCleanIdentifier(t *testing.T) {
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
	session.SetUserIdentifier("  user@company.com  ")
	if err := session.Save(base, baseRec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, c := range baseRec.Result().Cookies() {
		req.AddCookie(c)
	}

	oidc := &TraefikOidc{
		sessionManager: sm,
		logger:         NewLogger("debug"),
	}

	if ok := oidc.applyBypassUserHeaders(req, "test"); !ok {
		t.Fatalf("applyBypassUserHeaders returned false; bypass should be honored")
	}
	if v := req.Header.Get("X-Forwarded-User"); v != "user@company.com" {
		t.Fatalf("X-Forwarded-User = %q, want %q (trimmed)", v, "user@company.com")
	}
}
