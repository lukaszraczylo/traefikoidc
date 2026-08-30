package traefikoidc

import "testing"

// TestReplayCacheKey_NamespacedByIssuer verifies JTI replay entries are
// keyed by issuer (not a bare jti), so tokens issued by different OIDC
// providers sharing the process-global replay cache never collide (R142).
func TestReplayCacheKey_NamespacedByIssuer(t *testing.T) {
	if replayCacheKey("https://issuer-a.example.com", "jti-1") == replayCacheKey("https://issuer-b.example.com", "jti-1") {
		t.Fatal("same jti from different issuers must not share a replay key")
	}
	// Same issuer + jti is stable (idempotent) for the gate to work.
	k1 := replayCacheKey("issuer", "jti")
	k2 := replayCacheKey("issuer", "jti")
	if k1 != k2 {
		t.Fatal("same issuer+jti must be stable")
	}
	// Different jti under the same issuer must differ.
	if replayCacheKey("issuer", "jti-1") == replayCacheKey("issuer", "jti-2") {
		t.Fatal("different jti under the same issuer must differ")
	}
}
