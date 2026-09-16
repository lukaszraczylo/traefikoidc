package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
)

// TestForwardAuthorized_BearerStripPreservesTemplatedAuthorization is a
// regression test for the order in forwardAuthorized between the bearer
// Authorization strip and header-template application. Previously the strip
// (when source==sourceBearer && StripAuthorizationHeader, the default) ran
// AFTER template application, deleting an operator-supplied Authorization
// template (e.g. "Authorization: Bearer {{.AccessToken}}") and defeating
// its purpose. The strip must run first so an explicit template survives.
func TestForwardAuthorized_BearerStripPreservesTemplatedAuthorization(t *testing.T) {
	var forwarded *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	authTpl := template.Must(template.New("auth").Parse("Bearer {{.AccessToken}}"))
	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		next:                     next,
		stripAuthorizationHeader: true,
		headerTemplates: map[string]*template.Template{
			"Authorization": authTpl,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer raw-inbound-token")

	rec := httptest.NewRecorder()
	oidc.forwardAuthorized(rec, req, &principal{
		Source:      sourceBearer,
		AccessToken: "access-token-x",
	})

	d := forwarded.Header.Get("Authorization")
	// The operator's templated value must survive, replacing the raw inbound
	// token that would otherwise leak into downstream logs.
	if d != "Bearer access-token-x" {
		t.Fatalf("Authorization = %q, want %q", d, "Bearer access-token-x")
	}
}

// TestForwardAuthorized_BearerStripDefault is the regression-guard for the
// default config (strip on, no Authorization template): the raw inbound
// bearer header must still be removed before forwarding.
func TestForwardAuthorized_BearerStripDefault(t *testing.T) {
	var forwarded *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		next:                     next,
		stripAuthorizationHeader: true,
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer raw-inbound-token")

	rec := httptest.NewRecorder()
	oidc.forwardAuthorized(rec, req, &principal{Source: sourceBearer})

	if v := forwarded.Header.Get("Authorization"); v != "" {
		t.Fatalf("Authorization = %q, want empty (stripped)", v)
	}
}
