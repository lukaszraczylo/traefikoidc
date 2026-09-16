package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestR173_MinimalHeadersAlsoGatesGroupRoleHeaders verifies that
// minimalHeaders (documented to shrink forwarded headers so group-heavy users
// don't hit backend HTTP 431, issue #64) also gates X-User-Groups and
// X-User-Roles — the largest variably-sized forward headers — exactly like
// the X-Auth-Request-* family. Identity (X-Forwarded-User) and the
// allowedRolesAndGroups gate remain unconditional, so authorization is not
// weakened; only the forwarding of the bulky group/role headers is dropped.
func TestR173_MinimalHeadersAlsoGatesGroupRoleHeaders(t *testing.T) {
	tests := []struct {
		name            string
		minimalHeaders  bool
		expectUserGroup bool
	}{
		{"minimalHeaders=false forwards X-User-Groups", false, true},
		{"minimalHeaders=true drops X-User-Groups", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedHeaders http.Header
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			})

			sessionManager := createTestSessionManager(t)
			oidc := &TraefikOidc{
				next:                         next,
				logger:                       NewLogger("debug"),
				initComplete:                 make(chan struct{}),
				sessionManager:               sessionManager,
				firstRequestStarted:          1,
				metadataRefreshStartedAtomic: 1,
				issuerURL:                    "https://provider.example.com",
				minimalHeaders:               tt.minimalHeaders,
				groupClaimName:               "groups",
				extractClaimsFunc: func(token string) (map[string]interface{}, error) {
					if len(token) < 20 {
						return nil, nil
					}
					return map[string]interface{}{
						"email":  "user@example.com",
						"groups": []string{"team-a", "team-b"},
					}, nil
				},
			}
			close(oidc.initComplete)

			req := httptest.NewRequest("GET", "/protected", nil)
			rw := httptest.NewRecorder()

			session, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("get session: %v", err)
			}
			session.SetUserIdentifier("user@example.com")
			session.SetAuthenticated(true)
			// Seed a token so processAuthorizedRequest populates
			// principal.Claims with the group claims.
			session.SetAccessToken("test-access-token-abcdefghij")

			oidc.processAuthorizedRequest(rw, req, session, "https://example.com/callback")

			got := capturedHeaders.Get("X-User-Groups")
			if tt.expectUserGroup {
				if got == "" {
					t.Fatal("expected X-User-Groups to be forwarded, got empty")
				}
				if !strings.Contains(got, "team-a") {
					t.Fatalf("expected team-a in X-User-Groups, got %q", got)
				}
			} else {
				if got != "" {
					t.Fatalf("expected X-User-Groups to be dropped under minimalHeaders, got %q", got)
				}
			}

			// Identity must still be forwarded in both modes.
			if capturedHeaders.Get("X-Forwarded-User") != "user@example.com" {
				t.Fatalf("X-Forwarded-User must be set regardless of minimalHeaders, got %q", capturedHeaders.Get("X-Forwarded-User"))
			}
		})
	}
}
