package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServeHTTP_EventStream_EnforcesUserAllowlist is a regression for the
// SSE/WebSocket cutoff subjecting the streaming bypass to the user
// allowlist (isAllowedUser), mirroring the roles gate. Before the fix an
// authenticated user not in allowedUsers (or outside allowedUserDomains)
// could reach the backend just by setting Accept: text/event-stream.
func TestServeHTTP_EventStream_EnforcesUserAllowlist(t *testing.T) {
	sessionManager := createTestSessionManager(t)

	buildOidc := func(allowed map[string]struct{}, next http.Handler) *TraefikOidc {
		return &TraefikOidc{
			next:                         next,
			logger:                       NewLogger("error"),
			initComplete:                 make(chan struct{}),
			sessionManager:               sessionManager,
			firstRequestStarted:          1,
			metadataRefreshStartedAtomic: 1,
			issuerURL:                    "https://provider.example.com",
			allowedUsers:                 allowed,
		}
	}

	// SSE request carrying an authenticated session for user@example.com.
	buildReq := func(t *testing.T) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/events", nil)
		req.Header.Set("Accept", "text/event-stream")
		session, err := sessionManager.GetSession(req)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		session.SetUserIdentifier("user@example.com")
		if err := session.SetAuthenticated(true); err != nil {
			t.Fatalf("mark authenticated: %v", err)
		}
		rec := httptest.NewRecorder()
		if err := session.Save(req, rec); err != nil {
			t.Fatalf("save session: %v", err)
		}
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
		return req
	}

	t.Run("user_not_in_allowlist_rejected", func(t *testing.T) {
		nextCalled := false
		oidc := buildOidc(map[string]struct{}{"admin@example.com": {}},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true }))
		close(oidc.initComplete)

		rw := httptest.NewRecorder()
		oidc.ServeHTTP(rw, buildReq(t))

		if rw.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for SSE request from non-allowlisted user, got %d", rw.Code)
		}
		if nextCalled {
			t.Error("backend must NOT be called for a non-allowlisted user")
		}
	})

	t.Run("user_in_allowlist_forwarded", func(t *testing.T) {
		nextCalled := false
		oidc := buildOidc(map[string]struct{}{"user@example.com": {}},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true }))
		close(oidc.initComplete)

		rw := httptest.NewRecorder()
		oidc.ServeHTTP(rw, buildReq(t))

		if rw.Code != http.StatusOK && rw.Code != http.StatusUnauthorized {
			t.Fatalf("expected forward for allowlisted user, got %d", rw.Code)
		}
		if !nextCalled {
			t.Error("backend must be called for an allowlisted user")
		}
	})
}

// TestConfig_ValidateRejectsNegativeSessionMaxAge is a regression for a
// config-validation gap: a negative sessionMaxAge passed Validate(),
// producing a negative cookie MaxAge and an always-expired session
// (permanent lockout).
func TestConfig_ValidateRejectsNegativeSessionMaxAge(t *testing.T) {
	base := Config{
		ProviderURL:          "https://provider.example.com",
		CallbackURL:          "/callback",
		ClientID:             "client-id",
		ClientSecret:         "client-secret",
		SessionEncryptionKey: "01234567890123456789012345678901",
		LogLevel:             "info",
		RateLimit:            10,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline config should validate: %v", err)
	}

	neg := base
	neg.SessionMaxAge = -1
	err := neg.Validate()
	if err == nil {
		t.Fatal("expected Validate to reject negative sessionMaxAge")
	}
	if !strings.Contains(err.Error(), "sessionMaxAge") {
		t.Fatalf("expected sessionMaxAge error, got: %v", err)
	}
}

// TestGetSecurityHeadersApplier_AppliesCrossOriginAndPermissions is a
// regression for config no-effect: PermissionsPolicy and the three
// Cross-Origin-* fields were parsed and documented but never applied.
func TestGetSecurityHeadersApplier_AppliesCrossOriginAndPermissions(t *testing.T) {
	c := &Config{SecurityHeaders: &SecurityHeadersConfig{
		Enabled:                   true,
		PermissionsPolicy:         "geolocation=()",
		CrossOriginResourcePolicy: "same-origin",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
	}}
	applier := c.GetSecurityHeadersApplier()
	if applier == nil {
		t.Fatal("expected a non-nil header applier")
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	applier(rw, req)

	h := rw.Header()
	for name, want := range map[string]string{
		"Permissions-Policy":           "geolocation=()",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
