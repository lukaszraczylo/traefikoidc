package traefikoidc

// Regression test for FIX-34 (review-2026-09-10 finding at
// middleware.go:1169, low severity): forwardAuthorized truncated an
// oversized ID token to headerTemplateMaxLen (8192) bytes and still
// forwarded it in X-Auth-Request-Token. A truncated JWT is structurally
// invalid; a downstream that verifies the signature rejects it (fail
// closed, fine), but one that merely base64-decodes claims without
// verifying reads a corrupted, silently-wrong value. The header must be
// dropped instead, matching the fail-closed pattern already used elsewhere
// in forwardAuthorized (X-Forwarded-User / X-Auth-Request-User on a failed
// sanitization).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestForwardAuthorized_OversizedIDTokenDropsHeaderInsteadOfTruncating pins
// FIX-34: an ID token longer than headerTemplateMaxLen must not appear in
// X-Auth-Request-Token at all, truncated or otherwise.
func TestForwardAuthorized_OversizedIDTokenDropsHeaderInsteadOfTruncating(t *testing.T) {
	oidc := &TraefikOidc{
		next:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger: NewLogger("error"),
		// minimalHeaders defaults false: the X-Auth-Request-* block (where
		// X-Auth-Request-Token is set) only runs when it is false.
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	oversizedIDToken := strings.Repeat("a", headerTemplateMaxLen+1)
	p := &principal{
		Identifier: "user",
		IDToken:    oversizedIDToken,
	}
	oidc.forwardAuthorized(rw, req, p)

	if got := req.Header.Get("X-Auth-Request-Token"); got != "" {
		t.Fatalf("X-Auth-Request-Token must be dropped (not truncated) for an oversized ID token; got %d bytes, want header absent", len(got))
	}
}

// TestForwardAuthorized_IDTokenWithinLimitStillForwarded is the control: an
// ID token at or under the header budget must still be forwarded
// unmodified, so the fix does not regress the common case.
func TestForwardAuthorized_IDTokenWithinLimitStillForwarded(t *testing.T) {
	oidc := &TraefikOidc{
		next:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger: NewLogger("error"),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	idToken := "header.payload.signature"
	p := &principal{
		Identifier: "user",
		IDToken:    idToken,
	}
	oidc.forwardAuthorized(rw, req, p)

	if got := req.Header.Get("X-Auth-Request-Token"); got != idToken {
		t.Fatalf("X-Auth-Request-Token = %q, want the unmodified ID token %q", got, idToken)
	}
}
