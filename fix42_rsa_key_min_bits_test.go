package traefikoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

// TestValidateAlgKeyMatch_RejectsRSAKeyUnder2048Bits pins FIX-42: the
// RFC 7518 §3.3 minimum key-size rejection that 8640451 added to
// validateAlgKeyMatch (client_assertion.go:107) for private_key_jwt RS*/PS*
// signing keys, undocumented in that commit. FIX-25's sibling decision keeps
// the rejection as-is and records it in CHANGELOG.md; this test pins the
// contract with a named, matchable sentinel error so the rejection survives
// refactors and callers can detect it with errors.Is instead of matching a
// log string.
func TestValidateAlgKeyMatch_RejectsRSAKeyUnder2048Bits(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate 1024-bit test RSA key: %v", err)
	}

	err = validateAlgKeyMatch("RS256", key)
	if err == nil {
		t.Fatal("a 1024-bit RSA key must be rejected for RS256, got nil error")
	}
	if !errors.Is(err, ErrRSAKeyTooSmall) {
		t.Fatalf("error must wrap ErrRSAKeyTooSmall so callers can match it with errors.Is, got: %v", err)
	}
	const wantSubstring = "requires an RSA key of at least 2048 bits"
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("error message must state the requirement (%q), got: %v", wantSubstring, err)
	}
}

// TestValidateAlgKeyMatch_Accepts2048BitRSAKey is the boundary/positive
// case: a key at exactly the 2048-bit floor must be accepted.
func TestValidateAlgKeyMatch_Accepts2048BitRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate 2048-bit test RSA key: %v", err)
	}
	if err := validateAlgKeyMatch("RS256", key); err != nil {
		t.Fatalf("a 2048-bit RSA key must be accepted for RS256, got: %v", err)
	}
}
