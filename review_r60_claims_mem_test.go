package traefikoidc

import (
	"strings"
	"testing"
	"time"
)

// TestExtractGroupsRolesSingleString guards against reject-on-single-string for
// groups/roles claims. Some providers emit these as a bare string rather than
// a JSON array; the previous strict []interface{} branch returned an error,
// which dropped the identity (no allowedRolesAndGroups) or yielded a hard 403
// (allowedRolesAndGroups configured) for a valid user.
func TestExtractGroupsRolesSingleString(t *testing.T) {
	oidc := &TraefikOidc{
		groupClaimName: "groups",
		roleClaimName:  "roles",
		logger:         NewLogger(DefaultLogLevel),
	}

	groups, roles, err := oidc.extractGroupsAndRolesFromClaims(map[string]interface{}{
		"groups": "domain_users",         // single string
		"roles":  []interface{}{"admin"}, // array form still works
	})
	if err != nil {
		t.Fatalf("single-string groups claim should be accepted, got: %v", err)
	}
	if len(groups) != 1 || groups[0] != "domain_users" {
		t.Fatalf("groups = %v, want [domain_users]", groups)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", roles)
	}
}

// TestUniversalCacheMemoryUpdateDoesNotOverEvict guards the memory-limit eviction
// loop: updating an existing key whose NET growth fits the cap must not evict
// live (older, still-valid) entries. The old loop tested the FULL new size
// against currentMemory while the old size was still accounted, so a
// net-fitting update evicted otherwise-fit live entries.
func TestUniversalCacheMemoryUpdateDoesNotOverEvict(t *testing.T) {
	cache := NewUniversalCache(UniversalCacheConfig{
		Type:           CacheTypeMetadata,
		DefaultTTL:     time.Hour,
		MaxSize:        1000,
		MaxMemoryBytes: 100,
		Logger:         NewLogger(DefaultLogLevel),
	})
	defer cache.Close()

	live := strings.Repeat("L", 49) // size 49
	xold := strings.Repeat("x", 50) // size 50 -> total 99
	xnew := strings.Repeat("X", 51) // size 51, net growth +1 -> total 100 (fits)

	cache.Set("live", live, time.Hour) // oldest
	cache.Set("x", xold, time.Hour)
	cache.Set("x", xnew, time.Hour)

	if _, ok := cache.Get("live"); !ok {
		t.Fatalf("live entry was evicted by a net-fitting update (over-eviction on growth)")
	}
	if v, ok := cache.Get("x"); !ok || v != xnew {
		t.Fatalf("updated entry should be present with the new value")
	}
}
