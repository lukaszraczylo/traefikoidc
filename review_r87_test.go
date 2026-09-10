package traefikoidc

import (
	"net/http"
	"testing"
	"time"
)

// TestBackchannelLogout_RequiresExp is a regression: OIDC Back-Channel
// Logout 1.0 §2.4 makes exp REQUIRED and §2.6 requires it to be
// validated. The code previously accepted an exp-less logout token (the
// comment claimed "logout tokens don't have exp", which is false) and
// still invalidated the session, letting an unbounded-lifetime captured
// token be replayed.
func TestBackchannelLogout_RequiresExp(t *testing.T) {
	h := newR87LogoutHarness(t)
	claims := r87BaseClaims()
	delete(claims, "exp") // ensure absent
	if code := h.post(claims); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for logout token missing exp, got %d", code)
	}
}

// TestBackchannelLogout_RejectsExpiredExp is a regression: a logout token
// whose exp is already past must be rejected even when iat is fresh, as
// the spec's validation-is-like-ID-Tokens rule requires. Previously only
// iat was capped (15 min), so an expired exp was silently accepted and the
// session was still invalidated.
func TestBackchannelLogout_RejectsExpiredExp(t *testing.T) {
	h := newR87LogoutHarness(t)
	claims := r87BaseClaims()
	claims["iat"] = time.Now().Add(-2 * time.Minute).Unix()  // fresh (within 15 min)
	claims["exp"] = time.Now().Add(-10 * time.Minute).Unix() // expired beyond the 5-min skew
	if code := h.post(claims); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for logout token with expired exp, got %d", code)
	}
}

// TestBackchannelLogout_AcceptsValidExp is the control: an in-window
// exp must still be accepted and must invalidate the session.
func TestBackchannelLogout_AcceptsValidExp(t *testing.T) {
	h := newR87LogoutHarness(t)
	claims := r87BaseClaims()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	if code := h.post(claims); code != http.StatusOK {
		t.Fatalf("expected 200 for valid logout token, got %d", code)
	}
}
