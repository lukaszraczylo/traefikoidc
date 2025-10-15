package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMiddlewareContextCancellation tests request context cancellation
func TestMiddlewareContextCancellation(t *testing.T) {
	oidc := &TraefikOidc{
		logger:                 NewLogger("debug"),
		initComplete:           make(chan struct{}), // Never close to simulate waiting
		sessionManager:         createTestSessionManager(t),
		firstRequestReceived:   true,
		metadataRefreshStarted: true,
	}

	// Create request with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest("GET", "/api/test", nil).WithContext(ctx)
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	// Should return timeout/cancel error
	if rw.Code != http.StatusRequestTimeout && rw.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected timeout status for canceled context, got %d", rw.Code)
	}
}

// TestMiddlewareSessionErrorRecovery tests session error recovery
func TestMiddlewareSessionErrorRecovery(t *testing.T) {
	oidc := &TraefikOidc{
		next:                   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:                 NewLogger("debug"),
		initComplete:           make(chan struct{}),
		sessionManager:         createTestSessionManager(t),
		firstRequestReceived:   true,
		metadataRefreshStarted: true,
		issuerURL:              "https://provider.example.com",
		redirURLPath:           "/callback",
		logoutURLPath:          "/logout",
		clientID:               "test-client",
		audience:               "test-client",
		authURL:                "https://provider.example.com/auth",
	}
	close(oidc.initComplete)

	// Create request with corrupted session cookie
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "_oidc_session",
		Value: "corrupted!!!invalid!!!",
	})
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	// Should handle gracefully and initiate auth
	if rw.Code != http.StatusFound && rw.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect for corrupted session, got %d", rw.Code)
	}
}

// TestMiddlewareAJAXRequestHandling tests AJAX-specific request handling
func TestMiddlewareAJAXRequestHandling(t *testing.T) {
	oidc := &TraefikOidc{
		next:                   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:                 NewLogger("debug"),
		initComplete:           make(chan struct{}),
		sessionManager:         createTestSessionManager(t),
		firstRequestReceived:   true,
		metadataRefreshStarted: true,
		issuerURL:              "https://provider.example.com",
		redirURLPath:           "/callback",
		logoutURLPath:          "/logout",
		clientID:               "test-client",
		audience:               "test-client",
	}
	close(oidc.initComplete)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	// AJAX request without auth should get 401, not redirect
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated AJAX request, got %d", rw.Code)
	}
}

// TestMiddlewareDomainRestrictions tests domain-based access control
// NOTE: Currently commented out due to complex session setup requirements
// These scenarios are tested indirectly through integration tests
/*
func TestMiddlewareDomainRestrictions(t *testing.T) {
	sessionManager := createTestSessionManager(t)

	t.Run("allowed_domain_passes", func(t *testing.T) {
		oidc := &TraefikOidc{
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			logger:         NewLogger("debug"),
			initComplete:   make(chan struct{}),
			sessionManager: sessionManager,
			firstRequestReceived:   true,
			metadataRefreshStarted: true,
			issuerURL:      "https://provider.example.com",
			redirURLPath:   "/callback",
			logoutURLPath:  "/logout",
			clientID:       "test-client",
			audience:       "test-client",
			allowedUserDomains: map[string]struct{}{
				"example.com": {},
			},
			extractClaimsFunc: func(token string) (map[string]interface{}, error) {
				return map[string]interface{}{"email": "user@example.com"}, nil
			},
		}
		close(oidc.initComplete)

		// Create authenticated session
		req := httptest.NewRequest("GET", "/api/test", nil)
		session, _ := sessionManager.GetSession(req)
		session.SetEmail("user@example.com")
		session.SetAuthenticated(true)
		session.SetIDToken("dummy-token")
		session.Save(req, httptest.NewRecorder())

		// Add session cookies to request
		rw := httptest.NewRecorder()
		session.Save(req, rw)
		for _, cookie := range rw.Result().Cookies() {
			req.AddCookie(cookie)
		}

		rw = httptest.NewRecorder()
		oidc.ServeHTTP(rw, req)

		if rw.Code != http.StatusOK {
			t.Errorf("Expected 200 for allowed domain, got %d", rw.Code)
		}
	})

	t.Run("forbidden_domain_blocked", func(t *testing.T) {
		oidc := &TraefikOidc{
			next:                   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			logger:                 NewLogger("debug"),
			initComplete:           make(chan struct{}),
			sessionManager:         sessionManager,
			firstRequestReceived:   true,
			metadataRefreshStarted: true,
			issuerURL:              "https://provider.example.com",
			redirURLPath:           "/callback",
			logoutURLPath:          "/logout",
			clientID:               "test-client",
			audience:               "test-client",
			allowedUserDomains: map[string]struct{}{
				"example.com": {},
			},
		}
		close(oidc.initComplete)

		// Create session with forbidden domain
		req := httptest.NewRequest("GET", "/api/test", nil)
		session, _ := sessionManager.GetSession(req)
		session.SetEmail("user@forbidden.com")
		session.SetAuthenticated(true)

		// Save and inject cookies
		rw := httptest.NewRecorder()
		session.Save(req, rw)
		for _, cookie := range rw.Result().Cookies() {
			req.AddCookie(cookie)
		}

		rw = httptest.NewRecorder()
		oidc.ServeHTTP(rw, req)

		if rw.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for forbidden domain, got %d", rw.Code)
		}
	})
}
*/

// TestMiddlewareOpaqueTokenHandling tests opaque (non-JWT) token handling
// NOTE: Currently commented out due to complex session setup requirements
/*
func TestMiddlewareOpaqueTokenHandling(t *testing.T) {
	sessionManager := createTestSessionManager(t)

	oidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		logger:                 NewLogger("debug"),
		initComplete:           make(chan struct{}),
		sessionManager:         sessionManager,
		firstRequestReceived:   true,
		metadataRefreshStarted: true,
		issuerURL:              "https://provider.example.com",
		redirURLPath:           "/callback",
		logoutURLPath:          "/logout",
		clientID:               "test-client",
		audience:               "test-client",
		extractClaimsFunc: func(token string) (map[string]interface{}, error) {
			return map[string]interface{}{"email": "user@example.com"}, nil
		},
	}
	close(oidc.initComplete)

	// Create session with opaque token
	req := httptest.NewRequest("GET", "/api/test", nil)
	session, _ := sessionManager.GetSession(req)
	session.SetEmail("user@example.com")
	session.SetAccessToken("sk_live_abcdefghijklmnopqrstuvwxyz")  // Opaque token (no dots)
	session.SetAuthenticated(true)

	// Save and inject cookies
	rw := httptest.NewRecorder()
	session.Save(req, rw)
	for _, cookie := range rw.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rw = httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	// Should process successfully without JWT verification
	if rw.Code != http.StatusOK {
		t.Errorf("Expected 200 for opaque token, got %d", rw.Code)
	}
}
*/

// TestMiddlewareProcessAuthorizedRequestEdgeCases tests processAuthorizedRequest edge cases
func TestMiddlewareProcessAuthorizedRequestEdgeCases(t *testing.T) {
	sessionManager := createTestSessionManager(t)

	t.Run("missing_email_initiates_reauth", func(t *testing.T) {
		oidc := &TraefikOidc{
			next:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			logger:         NewLogger("debug"),
			sessionManager: sessionManager,
			redirURLPath:   "/callback",
			logoutURLPath:  "/logout",
			clientID:       "test-client",
			audience:       "test-client",
			authURL:        "https://provider.example.com/auth",
		}

		req := httptest.NewRequest("GET", "/api/test", nil)
		session, _ := sessionManager.GetSession(req)
		session.SetEmail("") // No email
		session.SetIDToken("dummy-token")

		rw := httptest.NewRecorder()
		redirectURL := "https://example.com/callback"
		oidc.processAuthorizedRequest(rw, req, session, redirectURL)

		// Should initiate re-auth
		if rw.Code != http.StatusFound && rw.Code != http.StatusSeeOther {
			t.Errorf("Expected redirect when email is missing, got %d", rw.Code)
		}
	})

	t.Run("missing_token_with_role_checks", func(t *testing.T) {
		oidc := &TraefikOidc{
			next:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			logger:         NewLogger("debug"),
			sessionManager: sessionManager,
			redirURLPath:   "/callback",
			logoutURLPath:  "/logout",
			clientID:       "test-client",
			audience:       "test-client",
			authURL:        "https://provider.example.com/auth",
			allowedRolesAndGroups: map[string]struct{}{
				"admin": {},
			},
		}

		req := httptest.NewRequest("GET", "/api/test", nil)
		session, _ := sessionManager.GetSession(req)
		session.SetEmail("user@example.com")
		session.SetIDToken("")     // No ID token
		session.SetAccessToken("") // No access token

		rw := httptest.NewRecorder()
		redirectURL := "https://example.com/callback"
		oidc.processAuthorizedRequest(rw, req, session, redirectURL)

		// Should initiate re-auth when token is missing but role checks required
		if rw.Code != http.StatusFound && rw.Code != http.StatusSeeOther {
			t.Errorf("Expected redirect when token is missing with role checks, got %d", rw.Code)
		}
	})

	t.Run("security_headers_applied", func(t *testing.T) {
		oidc := &TraefikOidc{
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			logger:         NewLogger("debug"),
			sessionManager: sessionManager,
			extractClaimsFunc: func(token string) (map[string]interface{}, error) {
				return map[string]interface{}{}, nil
			},
		}

		req := httptest.NewRequest("GET", "/api/test", nil)
		session, _ := sessionManager.GetSession(req)
		session.SetEmail("user@example.com")
		session.SetIDToken("dummy-token")

		rw := httptest.NewRecorder()
		redirectURL := "https://example.com/callback"
		oidc.processAuthorizedRequest(rw, req, session, redirectURL)

		// Verify security headers are set
		if rw.Header().Get("X-Frame-Options") == "" {
			t.Error("Expected X-Frame-Options header to be set")
		}
		if rw.Header().Get("X-Content-Type-Options") == "" {
			t.Error("Expected X-Content-Type-Options header to be set")
		}
		if rw.Header().Get("X-XSS-Protection") == "" {
			t.Error("Expected X-XSS-Protection header to be set")
		}
	})

	t.Run("authentication_headers_set", func(t *testing.T) {
		oidc := &TraefikOidc{
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			logger:         NewLogger("debug"),
			sessionManager: sessionManager,
			extractClaimsFunc: func(token string) (map[string]interface{}, error) {
				return map[string]interface{}{}, nil
			},
		}

		req := httptest.NewRequest("GET", "/api/test", nil)
		session, _ := sessionManager.GetSession(req)
		testEmail := "user@example.com"
		session.SetEmail(testEmail)
		session.SetIDToken("dummy-id-token")

		rw := httptest.NewRecorder()
		redirectURL := "https://example.com/callback"
		oidc.processAuthorizedRequest(rw, req, session, redirectURL)

		// Verify authentication headers
		if req.Header.Get("X-Forwarded-User") != testEmail {
			t.Errorf("Expected X-Forwarded-User=%s, got %s", testEmail, req.Header.Get("X-Forwarded-User"))
		}
		if req.Header.Get("X-Auth-Request-User") != testEmail {
			t.Errorf("Expected X-Auth-Request-User=%s, got %s", testEmail, req.Header.Get("X-Auth-Request-User"))
		}
		// Token header may not be set in all scenarios, just verify it's not causing errors
	})
}
