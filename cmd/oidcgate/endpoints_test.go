package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubMiddleware lets us test endpoint wiring without spinning up a full
// traefikoidc instance. Each test injects the behavior it wants.
type stubMiddleware struct {
	calls []stubCall
	fn    func(rw http.ResponseWriter, req *http.Request)
}

type stubCall struct {
	path   string
	header http.Header
}

func (s *stubMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s.calls = append(s.calls, stubCall{path: req.URL.Path, header: req.Header.Clone()})
	if s.fn != nil {
		s.fn(rw, req)
	}
}

func TestAuth_RewritesToSentinel_AndConverts302To401(t *testing.T) {
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, req *http.Request) {
			rw.Header().Set("Location", "https://idp.example/authorize?state=abc")
			rw.Header().Add("Set-Cookie", "_oidc_state=abc; Path=/")
			rw.WriteHeader(http.StatusFound)
		},
	}
	h := newAuthHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	req.Header.Set("X-Forwarded-Uri", "/protected/page")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", rec.Code)
	}
	if len(stub.calls) != 1 || stub.calls[0].path != sentinelPath {
		t.Fatalf("middleware path: want %q, got %v", sentinelPath, stub.calls)
	}
	if rec.Header().Get("X-Auth-Redirect") == "" {
		t.Error("X-Auth-Redirect should carry Location")
	}
}

func TestAuth_AuthenticatedReturnsHeadersAnd200(t *testing.T) {
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, req *http.Request) {
			// Middleware would stamp X-Forwarded-User on req then call next.
			req.Header.Set("X-Forwarded-User", "alice")
			newSuccessHandler().ServeHTTP(rw, req)
		},
	}
	h := newAuthHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Forwarded-User"); got != "alice" {
		t.Errorf("X-Forwarded-User mirrored: want alice, got %q", got)
	}
}

func TestStart_DelegatesWithSentinel_NoInterception(t *testing.T) {
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, req *http.Request) {
			rw.Header().Set("Location", "https://idp.example/authorize")
			rw.WriteHeader(http.StatusFound)
		},
	}
	h := newStartHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=/back", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("start: 302 must flow through, got %d", rec.Code)
	}
	if stub.calls[0].path != sentinelPath {
		t.Fatalf("start path rewrite: want %q, got %q", sentinelPath, stub.calls[0].path)
	}
}

func TestStart_ForwardsRdAsXForwardedURI(t *testing.T) {
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, req *http.Request) { rw.WriteHeader(http.StatusFound) },
	}
	h := newStartHandler(stub)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=/back/here", nil)
	h.ServeHTTP(rec, req)
	if got := stub.calls[0].header.Get("X-Forwarded-Uri"); got != "/back/here" {
		t.Fatalf("?rd should become X-Forwarded-Uri: want /back/here, got %q", got)
	}
}

func TestCallback_RewritesToConfiguredCallbackURL(t *testing.T) {
	var seenPath, seenQuery string
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, req *http.Request) {
			seenPath = req.URL.Path
			seenQuery = req.URL.RawQuery
			rw.WriteHeader(http.StatusOK)
		},
	}
	h := newCallbackHandler(stub, "/oauth2/callback")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=abc&state=xyz", nil)
	h.ServeHTTP(rec, req)

	if seenPath != "/oauth2/callback" {
		t.Fatalf("callback path: want /oauth2/callback, got %q", seenPath)
	}
	if seenQuery != "code=abc&state=xyz" {
		t.Fatalf("callback query must survive rewrite: want code=abc&state=xyz, got %q", seenQuery)
	}
}

func TestLogout_RewritesToConfiguredLogoutURL(t *testing.T) {
	var seenPath string
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, req *http.Request) {
			seenPath = req.URL.Path
			rw.WriteHeader(http.StatusOK)
		},
	}
	h := newLogoutHandler(stub, "/oauth2/logout")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", nil)
	h.ServeHTTP(rec, req)

	if seenPath != "/oauth2/logout" {
		t.Fatalf("logout path: want /oauth2/logout, got %q", seenPath)
	}
}
