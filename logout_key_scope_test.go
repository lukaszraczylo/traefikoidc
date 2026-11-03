package traefikoidc

import "testing"

func TestSessionInvalidationKeyScopedPerInstance(t *testing.T) {
	a := &TraefikOidc{tokenCache: &TokenCache{}}
	b := &TraefikOidc{tokenCache: &TokenCache{}}
	a.tokenCache.SetNamespace("https://kc/realms/a|c|c")
	b.tokenCache.SetNamespace("https://kc/realms/b|c|c")
	for _, kind := range []string{"sub", "sid", "jti"} {
		if a.buildSessionInvalidationKey(kind, "u1") == b.buildSessionInvalidationKey(kind, "u1") {
			t.Errorf("%s key shared across issuers", kind)
		}
	}
	if got := (&TraefikOidc{}).buildSessionInvalidationKey("sub", "u1"); got != "session_invalidation:sub:u1" {
		t.Errorf("namespace-less key changed: %q", got)
	}
}
