package traefikoidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
	"time"
)

// streamingRefreshSession stores a session whose tokens expire at exp and
// returns a WebSocket upgrade request carrying its cookies. An empty
// refreshToken leaves the refresh token unset; opaqueAccess stores a
// non-JWT access token so only the ID token carries an exp.
func streamingRefreshSession(t *testing.T, sm *SessionManager, exp time.Time, refreshToken string, opaqueAccess bool) *http.Request {
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
	claims := map[string]interface{}{
		"email":              "alice@example.com",
		"preferred_username": "alice-old",
		"exp":                float64(exp.Unix()),
	}
	session.SetIDToken(tokenWithGroups(t, claims))
	if opaqueAccess {
		session.SetAccessToken("opaque-access-token-without-dots")
	} else {
		session.SetAccessToken(tokenWithGroups(t, claims))
	}
	if refreshToken != "" {
		session.SetRefreshToken(refreshToken)
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
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	return req
}

func TestStreamingBypassRefresh(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	errInvalidGrant := errors.New(`token endpoint returned 400: {"error":"invalid_grant"}`)
	errTransient := errors.New("dial tcp 10.0.0.1:443: connect: connection refused")

	cases := []struct {
		name         string
		enabled      bool
		exp          time.Time
		refreshToken string
		opaqueAccess bool
		refreshErr   error
		wantStatus   int
		wantRefresh  int
		wantUsername string
	}{
		{name: "flag off keeps expired session forwarding", enabled: false, exp: past, refreshToken: "rt-old", wantStatus: http.StatusOK, wantRefresh: 0, wantUsername: "alice-old"},
		{name: "unexpired token skips refresh", enabled: true, exp: future, refreshToken: "rt-old", wantStatus: http.StatusOK, wantRefresh: 0, wantUsername: "alice-old"},
		{name: "expired token refreshes and forwards fresh claims", enabled: true, exp: past, refreshToken: "rt-old", wantStatus: http.StatusOK, wantRefresh: 1, wantUsername: "alice-new"},
		{name: "opaque access token uses ID token expiry", enabled: true, exp: past, refreshToken: "rt-old", opaqueAccess: true, wantStatus: http.StatusOK, wantRefresh: 1, wantUsername: "alice-new"},
		{name: "revoked grant is rejected", enabled: true, exp: past, refreshToken: "rt-old", refreshErr: errInvalidGrant, wantStatus: http.StatusUnauthorized, wantRefresh: 1},
		{name: "transient IdP failure still forwards", enabled: true, exp: past, refreshToken: "rt-old", refreshErr: errTransient, wantStatus: http.StatusOK, wantRefresh: 1, wantUsername: "alice-old"},
		{name: "no refresh token still forwards", enabled: true, exp: past, wantStatus: http.StatusOK, wantRefresh: 0, wantUsername: "alice-old"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
			if err != nil {
				t.Fatalf("NewSessionManager: %v", err)
			}
			t.Cleanup(func() {
				if err := sm.Shutdown(); err != nil {
					t.Errorf("Shutdown: %v", err)
				}
			})

			newClaims := map[string]interface{}{
				"email":              "alice@example.com",
				"preferred_username": "alice-new",
				"exp":                float64(future.Unix()),
			}
			exchanger := &EnhancedMockTokenExchanger{
				RefreshErr: tc.refreshErr,
				RefreshResponse: &TokenResponse{
					AccessToken:  tokenWithGroups(t, newClaims),
					IDToken:      tokenWithGroups(t, newClaims),
					RefreshToken: "rt-new",
				},
			}
			tmpl := template.Must(template.New("X-Forwarded-Preferred-Username").
				Funcs(headerTemplateFuncMap(claimsWhitelist(nil))).
				Option("missingkey=zero").
				Parse("{{.Claims.preferred_username}}"))

			initComplete := make(chan struct{})
			close(initComplete)
			var seen http.Header
			m := &TraefikOidc{
				logger:              GetSingletonNoOpLogger(),
				name:                "test",
				sessionManager:      sm,
				initComplete:        initComplete,
				extractClaimsFunc:   extractClaims,
				userIdentifierClaim: "email",
				tokenExchanger:      exchanger,
				tokenVerifier:       &EnhancedMockTokenVerifier{},
				streamingRefresh:    tc.enabled,
				headerTemplates:     map[string]*template.Template{"X-Forwarded-Preferred-Username": tmpl},
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen = r.Header.Clone()
					w.WriteHeader(http.StatusOK)
				}),
			}

			req := streamingRefreshSession(t, sm, tc.exp, tc.refreshToken, tc.opaqueAccess)
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, req)

			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tc.wantStatus)
			}
			if got := len(exchanger.RefreshCalls); got != tc.wantRefresh {
				t.Fatalf("refresh calls = %d, want %d", got, tc.wantRefresh)
			}
			if tc.wantStatus != http.StatusOK {
				if seen != nil {
					t.Fatal("next invoked for a rejected request")
				}
				return
			}
			if seen == nil {
				t.Fatal("next not invoked")
			}
			if got := seen.Get("X-Forwarded-Preferred-Username"); got != tc.wantUsername {
				t.Fatalf("X-Forwarded-Preferred-Username = %q, want %q", got, tc.wantUsername)
			}
			if tc.wantRefresh == 1 && tc.refreshErr == nil && len(rw.Result().Cookies()) == 0 {
				t.Fatal("refreshed session was not written back as a cookie")
			}
		})
	}
}

func TestStreamingRefreshConfigWiring(t *testing.T) {
	if CreateConfig().StreamingRefresh {
		t.Fatal("streamingRefresh must default to false")
	}
	for _, enabled := range []bool{false, true} {
		config := CreateConfig()
		config.ProviderURL = "https://provider.example.com"
		config.ClientID = "test-client-id"
		config.ClientSecret = "test-secret"
		config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		config.CallbackURL = "/callback"
		config.StreamingRefresh = enabled

		if got, ok := config.configToMap()["streamingRefresh"].(bool); !ok || got != enabled {
			t.Fatalf("configToMap streamingRefresh = %v (present=%v), want %v", got, ok, enabled)
		}
		oidc, err := NewWithContext(context.Background(), config, http.NotFoundHandler(), "test")
		if err != nil {
			t.Fatalf("NewWithContext: %v", err)
		}
		if oidc.streamingRefresh != enabled {
			t.Errorf("streamingRefresh = %v, want %v", oidc.streamingRefresh, enabled)
		}
		if err := oidc.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
}
