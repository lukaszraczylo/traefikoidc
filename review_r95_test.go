package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestForwardAuthorizedClearsForgedIdentityHeaders is an R95 regression:
// forwardAuthorized owns the identity headers it injects upstream. A
// client-supplied forged value (e.g. X-User-Groups: admin) must never
// survive to the backend when the middleware computes no value for that
// header (e.g. an authenticated user with no groups) — otherwise a
// backend authorizing on X-User-Groups would be spoofed. Before the fix
// the headers were only conditionally Set, never unconditionally Deleted.
func TestForwardAuthorizedClearsForgedIdentityHeaders(t *testing.T) {
	oidc := &TraefikOidc{
		next:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:         NewLogger("error"),
		groupClaimName: "groups",
		roleClaimName:  "roles",
		minimalHeaders: true,
	}

	// Authenticated user with NO groups and NO roles (p.Claims has neither).
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-Groups", "admin")
	req.Header.Set("X-User-Roles", "superuser")
	req.Header.Set("X-Forwarded-User", "forged@attacker.example")
	req.Header.Set("X-Auth-Request-User", "forged")
	rw := httptest.NewRecorder()
	p := &principal{Identifier: "realuser", Claims: map[string]interface{}{"sub": "subject"}}
	oidc.forwardAuthorized(rw, req, p)

	// Backend must not see any client-supplied value the middleware decided not to set.
	if got := req.Header.Get("X-User-Groups"); got != "" {
		t.Fatalf("forged X-User-Groups survived to backend: %q", got)
	}
	if got := req.Header.Get("X-User-Roles"); got != "" {
		t.Fatalf("forged X-User-Roles survived to backend: %q", got)
	}
	if got := req.Header.Get("X-Auth-Request-User"); got != "" {
		t.Fatalf("forged X-Auth-Request-User survived to backend: %q", got)
	}
	// X-Forwarded-User is re-emitted with the authoritative principal
	// identifier, overriding the forged value.
	if got := req.Header.Get("X-Forwarded-User"); got != "realuser" {
		t.Fatalf("expected X-Forwarded-User to be the authoritative identifier %q, got %q", "realuser", got)
	}
}
