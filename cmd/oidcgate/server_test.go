package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMux_RoutesAllEndpoints(t *testing.T) {
	stub := &stubMiddleware{
		fn: func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) },
	}
	mux := buildMux(&Config{
		Listen:    ":0",
		AuthPath:  "/oauth2/auth",
		StartPath: "/oauth2/start",
		OIDC: traefikoidcConfigStub{
			callbackURL: "/oauth2/callback",
			logoutURL:   "/oauth2/logout",
		}.AsOIDC(),
	}, stub, &readyStub{ready: true})

	cases := []struct {
		path   string
		method string
		want   int
	}{
		{"/healthz", http.MethodGet, http.StatusOK},
		{"/readyz", http.MethodGet, http.StatusOK},
		{"/oauth2/auth", http.MethodGet, http.StatusOK},
		{"/oauth2/start", http.MethodGet, http.StatusOK},
		{"/oauth2/callback", http.MethodGet, http.StatusOK},
		{"/oauth2/logout", http.MethodPost, http.StatusOK},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.want {
			t.Errorf("%s %s: want %d, got %d", c.method, c.path, c.want, rec.Code)
		}
	}
}
