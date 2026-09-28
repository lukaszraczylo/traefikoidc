package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCleanupOldCookies_UsesConfiguredCookiePath pins the fix for cookie
// cleanup under cookiePath. Session cookies are written at the configured
// cookiePath (EnhanceSessionSecurity), but CleanupOldCookies wrote its
// deletion cookies at a hardcoded "/". A browser deletes a cookie only when
// name, domain and path all match, so the cleanup removed nothing when
// cookiePath was set.
func TestCleanupOldCookies_UsesConfiguredCookiePath(t *testing.T) {
	cases := []struct {
		name       string
		cookiePath string
		wantPath   string
	}{
		{name: "configured path", cookiePath: "/app", wantPath: "/app"},
		{name: "default path", cookiePath: "", wantPath: "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm, err := NewSessionManager(
				"test-encryption-key-32-bytes-long!!",
				false, "app.example.com", "testpref", 0,
				newNoOpLogger(),
			)
			if err != nil {
				t.Fatalf("session manager: %v", err)
			}
			defer sm.Shutdown()
			sm.cookiePath = tc.cookiePath

			req := httptest.NewRequest(http.MethodGet, "/app/page", nil)
			req.Host = "app.example.com"
			req.AddCookie(&http.Cookie{Name: "testpref_sess", Value: "x"})
			rw := httptest.NewRecorder()

			sm.CleanupOldCookies(rw, req)

			deleted := rw.Result().Cookies()
			if len(deleted) == 0 {
				t.Fatal("expected deletion cookies for the other domains")
			}
			for _, c := range deleted {
				if c.Path != tc.wantPath {
					t.Errorf("deletion cookie %s for domain %s has Path %q, want %q", c.Name, c.Domain, c.Path, tc.wantPath)
				}
			}
		})
	}
}
