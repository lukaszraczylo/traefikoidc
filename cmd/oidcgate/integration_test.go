package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc"
)

// fakeProviderHost is a synthetic hostname used in place of the httptest.Server's
// 127.0.0.1 address. traefikoidc's URL validator blocks loopback IPs
// unconditionally; a non-loopback hostname passes the check. The custom HTTP
// client returned by mockHTTPClient rewires all dials for this host to the
// actual test-server port, so the mock IdP still receives every request.
const fakeProviderHost = "test-oidc-provider.local"

// mockHTTPClient returns an *http.Client whose dialer transparently redirects
// connections to fakeProviderHost to the real httptest.Server address.
func mockHTTPClient(realAddr string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return dialer.DialContext(ctx, network, addr)
			}
			if host == fakeProviderHost {
				addr = realAddr
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: transport}
}

// newMockIdP returns an httptest.Server that serves the minimal OIDC
// discovery surface required by traefikoidc.NewWithContext to bootstrap
// — discovery doc + an empty JWKS. All URLs in the discovery doc use
// fakeProviderHost so they pass the middleware's URL security validator.
func newMockIdP(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	fakeBase := "http://" + fakeProviderHost
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) {
		discovery := map[string]any{
			"issuer":                                fakeBase,
			"authorization_endpoint":                fakeBase + "/authorize",
			"token_endpoint":                        fakeBase + "/token",
			"jwks_uri":                              fakeBase + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(discovery)
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"keys":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// buildTestConfig produces a Config that points at the fake provider hostname
// (which the custom HTTP client redirects to the real mock server) and uses
// a known-good SessionEncryptionKey + safe path defaults.
func buildTestConfig(srv *httptest.Server) *Config {
	// realAddr is HOST:PORT of the httptest server (e.g. "127.0.0.1:56789").
	realAddr := srv.Listener.Addr().String()
	cfg := &Config{
		Listen:    "127.0.0.1:0", // unused — we drive the mux directly via httptest
		AuthPath:  "/oauth2/auth",
		StartPath: "/oauth2/start",
		OIDC: traefikoidc.Config{
			ProviderURL:          "http://" + fakeProviderHost,
			ClientID:             "test-client",
			ClientSecret:         "test-secret",
			SessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CallbackURL:          "/oauth2/callback",
			LogoutURL:            "/oauth2/logout",
			TrustForwardedURI:    true,
			EnablePKCE:           true,
			HTTPClient:           mockHTTPClient(realAddr),
		},
	}
	return cfg
}

// buildIntegrationStack builds the same wiring main.go builds: real
// middleware constructed against the mock IdP, success handler as next,
// mux on top.
func buildIntegrationStack(t *testing.T, idp *httptest.Server) (http.Handler, *traefikoidc.TraefikOidc) {
	t.Helper()
	cfg := buildTestConfig(idp)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mw, err := traefikoidc.NewWithContext(ctx, &cfg.OIDC, newSuccessHandler(), "oidcgate-test")
	if err != nil {
		t.Fatalf("NewWithContext: %v", err)
	}
	mux := buildMux(cfg, mw, mw)
	return mux, mw
}

func TestIntegration_UnauthenticatedAuthReturns401WithRedirect(t *testing.T) {
	idp := newMockIdP(t)
	mux, _ := buildIntegrationStack(t, idp)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("X-Auth-Redirect")
	if loc == "" {
		t.Fatal("X-Auth-Redirect should carry the IdP authorize URL")
	}
	if !strings.HasPrefix(loc, "http://"+fakeProviderHost+"/authorize") {
		t.Errorf("X-Auth-Redirect should point at the mock IdP authorize endpoint, got %q", loc)
	}
	if cookies := rec.Header().Values("Set-Cookie"); len(cookies) == 0 {
		t.Error("expected at least one Set-Cookie (state/PKCE/nonce) on 401")
	}
}

func TestIntegration_StartRedirectsToIdPWithStateAndPKCE(t *testing.T) {
	idp := newMockIdP(t)
	mux, _ := buildIntegrationStack(t, idp)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=/dashboard", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status: want 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://"+fakeProviderHost+"/authorize") {
		t.Fatalf("Location: want prefix http://%s/authorize, got %q", fakeProviderHost, loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Errorf("Location should include state= param, got %q", loc)
	}
	if !strings.Contains(loc, "code_challenge=") {
		t.Errorf("Location should include code_challenge= param (PKCE), got %q", loc)
	}
}

func TestIntegration_HealthzAlways200(t *testing.T) {
	idp := newMockIdP(t)
	mux, _ := buildIntegrationStack(t, idp)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", rec.Code)
	}
}

func TestIntegration_ReadyzBecomes200AfterDiscovery(t *testing.T) {
	idp := newMockIdP(t)
	mux, mw := buildIntegrationStack(t, idp)

	// Hit /oauth2/auth once to trigger metadata discovery (the middleware
	// performs discovery lazily on first request).
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil))

	// Poll Ready() until true or timeout.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mw.Ready() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !mw.Ready() {
		t.Fatal("middleware should be Ready() within 3s after first request triggered discovery")
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz post-discovery: want 200, got %d", rec.Code)
	}
}
