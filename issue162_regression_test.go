package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
	"time"
)

// Issue #162: the SSE/WebSocket bypass forwarded only X-Forwarded-User, not
// the operator-configured `headers`. Backends that authenticate the proxy
// with a shared-secret header (Frigate proxy auth) answered 401 on /ws while
// normal requests, which go through forwardAuthorized, kept working.

func issue162Templates(t *testing.T, headers map[string]string) map[string]*template.Template {
	t.Helper()
	funcMap := headerTemplateFuncMap(claimsWhitelist(nil))
	out := make(map[string]*template.Template, len(headers))
	for name, value := range headers {
		tmpl, err := template.New(name).Funcs(funcMap).Option("missingkey=zero").Parse(value)
		if err != nil {
			t.Fatalf("parse template %s: %v", name, err)
		}
		out[name] = tmpl
	}
	return out
}

// issue162Request builds a request carrying a saved authenticated session.
// idClaims and accessClaims are optional; nil leaves that token unset.
func issue162Request(t *testing.T, sm *SessionManager, idClaims, accessClaims map[string]interface{}) *http.Request {
	t.Helper()
	setupReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/ws", nil)
	session, err := sm.GetSession(setupReq)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("SetAuthenticated: %v", err)
	}
	session.SetUserIdentifier("alice@example.com")
	if idClaims != nil {
		session.SetIDToken(tokenWithGroups(t, idClaims))
	}
	if accessClaims != nil {
		session.SetAccessToken(tokenWithGroups(t, accessClaims))
	}
	rr := httptest.NewRecorder()
	if err := session.Save(setupReq, rr); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/ws", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func issue162Middleware(t *testing.T, sm *SessionManager, templates map[string]*template.Template, seen *http.Header) *TraefikOidc {
	t.Helper()
	initComplete := make(chan struct{})
	close(initComplete)
	return &TraefikOidc{
		logger:            GetSingletonNoOpLogger(),
		name:              "test",
		sessionManager:    sm,
		initComplete:      initComplete,
		extractClaimsFunc: extractClaims,
		groupClaimName:    "groups",
		headerTemplates:   templates,
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*seen = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}),
	}
}

func issue162SessionManager(t *testing.T) *SessionManager {
	t.Helper()
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() {
		if err := sm.Shutdown(); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return sm
}

func TestIssue162_StreamingBypassForwardsHeaderTemplates(t *testing.T) {
	templates := map[string]string{
		"X-Proxy-Secret":                 "s3cret",
		"X-Forwarded-Preferred-Username": "{{.Claims.preferred_username}}",
		"X-Forwarded-Groups":             "{{range $i, $e := .Claims.groups}}{{if $i}},{{end}}{{$e}}{{end}}",
	}
	idClaims := map[string]interface{}{
		"preferred_username": "alice",
		"groups":             []string{"admins", "viewers"},
	}

	cases := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{"websocket", func(r *http.Request) {
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "Upgrade")
		}},
		{"sse", func(r *http.Request) {
			r.Header.Set("Accept", "text/event-stream")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := issue162SessionManager(t)
			var seen http.Header
			m := issue162Middleware(t, sm, issue162Templates(t, templates), &seen)

			req := issue162Request(t, sm, idClaims, nil)
			tc.prepare(req)
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req)

			if seen == nil {
				t.Fatalf("next not invoked (status=%d body=%q)", rw.Code, rw.Body.String())
			}
			want := map[string]string{
				"X-Forwarded-User":               "alice@example.com",
				"X-Proxy-Secret":                 "s3cret",
				"X-Forwarded-Preferred-Username": "alice",
				"X-Forwarded-Groups":             "admins,viewers",
			}
			for h, v := range want {
				if got := seen.Get(h); got != v {
					t.Errorf("%s = %q, want %q", h, got, v)
				}
			}
		})
	}
}

// Opaque-ID-token providers: normal requests render templates from
// access-token claims when the session has no ID token, so the bypass must too.
func TestIssue162_StreamingBypassTemplatesFallBackToAccessTokenClaims(t *testing.T) {
	sm := issue162SessionManager(t)
	var seen http.Header
	m := issue162Middleware(t, sm, issue162Templates(t, map[string]string{
		"X-Forwarded-Preferred-Username": "{{.Claims.preferred_username}}",
	}), &seen)

	req := issue162Request(t, sm, nil, map[string]interface{}{"preferred_username": "bob"})
	req.Header.Set("Accept", "text/event-stream")
	m.ServeHTTP(httptest.NewRecorder(), req)

	if seen == nil {
		t.Fatal("next not invoked")
	}
	if got := seen.Get("X-Forwarded-Preferred-Username"); got != "bob" {
		t.Fatalf("X-Forwarded-Preferred-Username = %q, want %q", got, "bob")
	}
}

// An unauthenticated upgrade must still be rejected before any template
// (which can carry a shared secret) is rendered onto the request.
func TestIssue162_StreamingBypassRejectsUnauthenticatedWithoutTemplates(t *testing.T) {
	sm := issue162SessionManager(t)
	var seen http.Header
	m := issue162Middleware(t, sm, issue162Templates(t, map[string]string{"X-Proxy-Secret": "s3cret"}), &seen)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	if seen != nil {
		t.Fatal("next invoked for unauthenticated upgrade")
	}
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	if req.Header.Get("X-Proxy-Secret") != "" {
		t.Fatal("shared-secret template rendered onto a rejected request")
	}
}

// Now that the bypass forwards proxy credentials (#162), it must honor
// IdP-initiated logout like the normal path does; otherwise a logged-out
// cookie keeps opening WebSocket/SSE with the shared secret attached.
func TestIssue162_StreamingBypassRejectsIdPLoggedOutSession(t *testing.T) {
	idClaims := map[string]interface{}{
		"sid": "sess-162",
		"sub": "alice",
		"iat": float64(time.Now().Add(-time.Minute).Unix()),
	}
	cases := []struct {
		name       string
		invalidate bool
		wantStatus int
	}{
		{"active session forwards", false, http.StatusOK},
		{"logged-out session rejected", true, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := issue162SessionManager(t)
			cache := NewCache()
			defer cache.Close()

			var seen http.Header
			m := issue162Middleware(t, sm, issue162Templates(t, map[string]string{"X-Proxy-Secret": "s3cret"}), &seen)
			m.enableBackchannelLogout = true
			m.sessionInvalidationCache = cache
			if tc.invalidate {
				if err := m.invalidateSession("sess-162", ""); err != nil {
					t.Fatalf("invalidateSession: %v", err)
				}
			}

			req := issue162Request(t, sm, idClaims, nil)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req)

			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tc.wantStatus)
			}
			if forwarded := seen != nil; forwarded != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("next invoked = %v, want %v", forwarded, tc.wantStatus == http.StatusOK)
			}
		})
	}
}
