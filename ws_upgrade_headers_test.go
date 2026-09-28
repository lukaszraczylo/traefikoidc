package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
)

// Regression test for the WebSocket/SSE upgrade path (upstream issue #162).
//
// Upgrades skip the OIDC redirect but are still authenticated through the
// session cookie, so they must receive the headers configured in the
// middleware - a proxy-auth backend that checks a shared secret (e.g. Frigate,
// which requires X-Proxy-Secret on its auth subrequest) answers 401 on the
// handshake otherwise, while plain HTTP requests keep working.
//
// This fails if applyTemplatedHeaders stops rendering claims, or if the bypass
// path stops calling it.
func TestApplyTemplatedHeadersRendersClaims(t *testing.T) {
	oidc := &TraefikOidc{
		logger: NewLogger("error"),
		headerTemplates: map[string]*template.Template{
			"X-Forwarded-Preferred-Username": template.Must(template.New("u").Parse("{{.Claims.preferred_username}}")),
			"X-Forwarded-Groups":             template.Must(template.New("g").Parse("{{range $i, $e := .Claims.groups}}{{if $i}},{{end}}{{$e}}{{end}}")),
			"X-Proxy-Secret":                 template.Must(template.New("s").Parse("shared-secret")),
		},
	}

	// The bypass path builds the same templateData map from the session; the
	// upgrade request itself carries Upgrade: websocket.
	req := httptest.NewRequest(http.MethodGet, "http://frigate.test/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	oidc.applyTemplatedHeaders(req, map[string]interface{}{
		"Claims": map[string]interface{}{
			"preferred_username": "jsapede",
			"groups":             []string{"admin", "viewer"},
		},
	})

	for name, want := range map[string]string{
		"X-Forwarded-Preferred-Username": "jsapede",
		"X-Forwarded-Groups":             "admin,viewer",
		"X-Proxy-Secret":                 "shared-secret",
	} {
		if got := req.Header.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}
