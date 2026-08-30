package traefikoidc

import "testing"

// TestRedactToken_ShortStableHash verifies redactToken (helpers.go) returns a
// short stable hash rather than the raw credential, so debug logs of token
// responses never leak full access/refresh/id tokens (R138).
func TestRedactToken_ShortStableHash(t *testing.T) {
	tok := "a-very-long-access-token-value-that-must-not-be-logged"
	h := redactToken(tok)

	// Returns 8 hex chars, not the raw token.
	if len(h) != 8 {
		t.Fatalf("expected 8-hex-char hash, got %q (len %d)", h, len(h))
	}
	if h == tok {
		t.Fatalf("redactToken returned the raw token: %q", h)
	}

	// Deterministic for the same input.
	if h2 := redactToken(tok); h2 != h {
		t.Fatalf("redactToken not deterministic: %q vs %q", h, h2)
	}

	// Empty -> explicit marker.
	if got := redactToken(""); got != "(empty)" {
		t.Fatalf("expected (empty) for empty token, got %q", got)
	}
}
