package traefikoidc

import (
	"errors"
	"fmt"
	"testing"
)

// Only a real audience mismatch may select the lenient-audience path; an
// error text that merely embeds the attacker-chosen kid must not.
func TestAudienceErrorClassifiedBySentinel(t *testing.T) {
	if !errors.Is(fmt.Errorf("standard claim verification failed: %w", verifyAudience("x", "y")), errInvalidAudience) {
		t.Fatal("audience mismatch not recognized through wrapping")
	}
	if errors.Is(verifyAudience("y", "y"), errInvalidAudience) {
		t.Fatal("matching audience classified as mismatch")
	}
	for _, kid := range []string{"audience", "invalid audience"} {
		err := fmt.Errorf("failed to get public key: no matching public key found for kid: %s", kid)
		if errors.Is(err, errInvalidAudience) {
			t.Errorf("kid %q fooled the audience classifier", kid)
		}
	}
}
