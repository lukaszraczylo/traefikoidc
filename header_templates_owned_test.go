package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"text/template"
)

func ownedHeaderOIDC(t *testing.T, names ...string) *TraefikOidc {
	t.Helper()
	m := map[string]*template.Template{}
	for _, n := range names {
		m[n] = template.Must(template.New(n).Option("missingkey=zero").Parse("{{.Claims.tenant}}"))
	}
	return &TraefikOidc{logger: NewLogger("error"), headerTemplates: m}
}

// A templated header the middleware owns must never carry a client value:
// an optional claim that renders empty must leave the header absent.
func TestTemplatedHeaderDropsClientSpoof(t *testing.T) {
	o := ownedHeaderOIDC(t, "X-Tenant")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Tenant", "admin-corp")
	o.applyHeaderTemplates(req, &principal{Claims: map[string]interface{}{"sub": "u"}})
	if got := req.Header.Get("X-Tenant"); got != "" {
		t.Fatalf("client-supplied X-Tenant reached the backend: %q", got)
	}
}

func TestTemplatedHeaderRenderedValueWins(t *testing.T) {
	o := ownedHeaderOIDC(t, "X-Tenant")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Tenant", "evil")
	o.applyHeaderTemplates(req, &principal{Claims: map[string]interface{}{"tenant": "acme"}})
	if got := req.Header.Get("X-Tenant"); got != "acme" {
		t.Fatalf("X-Tenant = %q, want acme", got)
	}
}

// Identity headers are injected before templates run; an empty render must
// not clobber them, and Authorization stays as received.
func TestTemplatedHeaderKeepsIdentityAndAuthorization(t *testing.T) {
	o := ownedHeaderOIDC(t, "X-Forwarded-User", "Authorization")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Authorization", "Bearer abc")
	o.applyHeaderTemplates(req, &principal{Claims: map[string]interface{}{"sub": "u"}})
	if got := req.Header.Get("X-Forwarded-User"); got != "alice" {
		t.Fatalf("identity header clobbered: %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer abc" {
		t.Fatalf("Authorization changed: %q", got)
	}
}
