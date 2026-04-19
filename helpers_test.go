package traefikoidc

import (
	"regexp"
	"testing"
)

// TestNewUUIDv4 verifies the in-house UUID v4 generator produces RFC 4122
// compliant identifiers. Locks in the replacement for github.com/google/uuid
// — a regression here would weaken the CSRF token used in the OIDC flow.
func TestNewUUIDv4(t *testing.T) {
	rfc4122v4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	const samples = 1000
	seen := make(map[string]struct{}, samples)
	for i := 0; i < samples; i++ {
		got, err := newUUIDv4()
		if err != nil {
			t.Fatalf("newUUIDv4 failed: %v", err)
		}
		if !rfc4122v4.MatchString(got) {
			t.Fatalf("UUID %q does not match RFC 4122 v4 format", got)
		}
		if _, dup := seen[got]; dup {
			t.Fatalf("duplicate UUID emitted within %d samples: %q", samples, got)
		}
		seen[got] = struct{}{}
	}
}
