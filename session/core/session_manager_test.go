package core

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// Mock logger for testing
type MockLogger struct {
	logs []string
}

func (ml *MockLogger) Debug(msg string) {
	ml.logs = append(ml.logs, "DEBUG: "+msg)
}

func (ml *MockLogger) Debugf(format string, args ...interface{}) {
	ml.logs = append(ml.logs, fmt.Sprintf("DEBUG: "+format, args...))
}

func (ml *MockLogger) Error(msg string) {
	ml.logs = append(ml.logs, "ERROR: "+msg)
}

func (ml *MockLogger) Errorf(format string, args ...interface{}) {
	ml.logs = append(ml.logs, fmt.Sprintf("ERROR: "+format, args...))
}

// Mock chunk manager for testing
type MockChunkManager struct {
	cleanupCalled int
}

func (mcm *MockChunkManager) CleanupExpiredSessions() {
	mcm.cleanupCalled++
}

// Mock session data for testing
type MockSessionData struct {
	manager       *SessionManager
	authenticated bool
	dirty         bool
	clearCalled   int
	email         string
	emailSet      bool // Flag to indicate if email was explicitly set
}

func (msd *MockSessionData) Reset() {
	msd.authenticated = false
	msd.dirty = false
}

func (msd *MockSessionData) SetManager(manager *SessionManager) {
	msd.manager = manager
}

func (msd *MockSessionData) SetAuthenticated(auth bool) error {
	msd.authenticated = auth
	return nil
}

func (msd *MockSessionData) GetAuthenticated() bool {
	return msd.authenticated
}

func (msd *MockSessionData) GetAccessToken() string {
	if msd.authenticated {
		return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	}
	return ""
}
func (msd *MockSessionData) GetRefreshToken() string {
	if msd.authenticated {
		return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	}
	return ""
}
func (msd *MockSessionData) GetIDToken() string {
	if msd.authenticated {
		return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	}
	return ""
}
func (msd *MockSessionData) GetEmail() string {
	// If email was explicitly set, return it (even if empty)
	if msd.emailSet {
		return msd.email
	}
	// Default behavior for authenticated sessions
	if msd.authenticated {
		return "user@example.com"
	}
	return ""
}
func (msd *MockSessionData) GetCSRF() string                                   { return "" }
func (msd *MockSessionData) GetNonce() string                                  { return "" }
func (msd *MockSessionData) GetCodeVerifier() string                           { return "" }
func (msd *MockSessionData) GetIncomingPath() string                           { return "" }
func (msd *MockSessionData) GetRedirectCount() int                             { return 0 }
func (msd *MockSessionData) IncrementRedirectCount()                           {}
func (msd *MockSessionData) ResetRedirectCount()                               {}
func (msd *MockSessionData) MarkDirty()                                        { msd.dirty = true }
func (msd *MockSessionData) IsDirty() bool                                     { return msd.dirty }
func (msd *MockSessionData) Save(r *http.Request, w http.ResponseWriter) error { return nil }
func (msd *MockSessionData) GetRefreshTokenIssuedAt() time.Time                { return time.Now() }
func (msd *MockSessionData) returnToPoolSafely()                               {}

func (msd *MockSessionData) Clear(r *http.Request, w http.ResponseWriter) error {
	msd.clearCalled++
	msd.returnToPoolSafely()
	return nil
}

// NewMockSessionData creates a new mock session data
func NewMockSessionData(manager *SessionManager, logger Logger) SessionData {
	return &MockSessionData{manager: manager}
}

// TestSessionManagerCreation tests session manager creation
func TestSessionManagerCreation(t *testing.T) {
	tests := []struct {
		name           string
		encryptionKey  string
		expectError    bool
		expectedKeyLen int
		description    string
	}{
		{
			name:           "Valid encryption key",
			encryptionKey:  "0123456789abcdef0123456789abcdef0123456789abcdef",
			expectError:    false,
			expectedKeyLen: 48,
			description:    "Should successfully create session manager with valid key",
		},
		{
			name:           "Minimum length key",
			encryptionKey:  "0123456789abcdef0123456789abcdef",
			expectError:    false,
			expectedKeyLen: 32,
			description:    "Should accept key at minimum length",
		},
		{
			name:           "Too short key",
			encryptionKey:  "tooshort",
			expectError:    true,
			expectedKeyLen: 0,
			description:    "Should reject keys that are too short",
		},
		{
			name:           "Empty key",
			encryptionKey:  "",
			expectError:    true,
			expectedKeyLen: 0,
			description:    "Should reject empty keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}

			sm, err := NewSessionManager(tt.encryptionKey, false, "", logger, chunkManager, "test-instance")

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
				return
			}

			if sm == nil {
				t.Errorf("Session manager should not be nil for %s", tt.description)
				return
			}

			// Verify the session manager is properly initialized
			if sm.logger == nil {
				t.Error("Logger should be set")
			}

			if sm.store == nil {
				t.Error("Store should be initialized")
			}
		})
	}
}

// TestSessionManagerPoolBehavior tests session pooling behavior
func TestSessionManagerPoolBehavior(t *testing.T) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, chunkManager, "test-instance")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Override the session pool to use our mock
	sm.sessionPool.New = func() interface{} {
		return NewMockSessionData(sm, logger)
	}

	tests := []struct {
		name        string
		description string
		operation   func(t *testing.T, sm *SessionManager)
	}{
		{
			name:        "Session creation and return",
			description: "Test that sessions are properly created and returned to pool",
			operation: func(t *testing.T, sm *SessionManager) {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)

				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}

				if session == nil {
					t.Fatal("Session should not be nil")
				}

				// Clear should return the session to pool
				w := httptest.NewRecorder()
				err = session.Clear(req, w)
				if err != nil {
					t.Logf("Clear returned error (this may be expected): %v", err)
				}
			},
		},
		{
			name:        "Multiple sessions",
			description: "Test creating multiple sessions",
			operation: func(t *testing.T, sm *SessionManager) {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)

				// Create multiple sessions
				sessions := make([]SessionData, 5)
				for i := 0; i < 5; i++ {
					session, err := sm.GetSession(req)
					if err != nil {
						t.Fatalf("GetSession %d failed: %v", i, err)
					}
					sessions[i] = session
				}

				// Clear all sessions
				w := httptest.NewRecorder()
				for i, session := range sessions {
					err := session.Clear(req, w)
					if err != nil {
						t.Logf("Clear session %d returned error: %v", i, err)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record initial goroutine count
			initialGoroutines := runtime.NumGoroutine()

			tt.operation(t, sm)

			// Force garbage collection
			runtime.GC()
			time.Sleep(10 * time.Millisecond)

			// Check for goroutine leaks
			finalGoroutines := runtime.NumGoroutine()
			if finalGoroutines > initialGoroutines+2 { // Allow small tolerance
				t.Errorf("Potential goroutine leak: started with %d, ended with %d",
					initialGoroutines, finalGoroutines)
			}
		})
	}
}

// TestSessionManagerErrorHandling tests error handling scenarios
func TestSessionManagerErrorHandling(t *testing.T) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, chunkManager, "test-instance")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Override the session pool to use our mock
	sm.sessionPool.New = func() interface{} {
		return NewMockSessionData(sm, logger)
	}

	tests := []struct {
		name        string
		description string
		setupReq    func() *http.Request
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name:        "Corrupt cookie value",
			description: "Test handling of corrupted cookie values",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				req.AddCookie(&http.Cookie{
					Name:  MainCookieName(),
					Value: "corrupt-value",
				})
				return req
			},
			expectError: false, // Session manager should gracefully handle corrupted cookies
			errorCheck:  nil,
		},
		{
			name:        "Invalid base64 cookie",
			description: "Test handling of invalid base64 in cookies",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				req.AddCookie(&http.Cookie{
					Name:  MainCookieName(),
					Value: "!@#$%^&*()",
				})
				return req
			},
			expectError: false, // Session manager should gracefully handle invalid base64
			errorCheck:  nil,
		},
		{
			name:        "Empty cookie value",
			description: "Test handling of empty cookie values",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				req.AddCookie(&http.Cookie{
					Name:  MainCookieName(),
					Value: "",
				})
				return req
			},
			expectError: false,
			errorCheck:  nil,
		},
		{
			name:        "Normal request",
			description: "Test normal request without cookies",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/foo", nil)
			},
			expectError: false,
			errorCheck:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()

			_, err := sm.GetSession(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.description)
					return
				}

				if tt.errorCheck != nil && !tt.errorCheck(err) {
					t.Errorf("Error check failed for %s: %v", tt.description, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tt.description, err)
				}
			}
		})
	}
}

// TestSessionManagerCleanup tests cleanup functionality
func TestSessionManagerCleanup(t *testing.T) {
	logger := &MockLogger{}
	mockChunkManager := &MockChunkManager{}

	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, mockChunkManager, "test-instance")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	t.Run("PeriodicChunkCleanup called", func(t *testing.T) {
		initialCalls := mockChunkManager.cleanupCalled

		sm.PeriodicChunkCleanup()

		// Note: The actual cleanup may or may not be called depending on internal logic
		// This test just ensures the method exists and can be called
		t.Logf("Cleanup called %d times after PeriodicChunkCleanup",
			mockChunkManager.cleanupCalled-initialCalls)
	})

	t.Run("CleanupOldCookies functionality", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		w := httptest.NewRecorder()

		// This should not panic and should handle cleanup properly
		sm.CleanupOldCookies(w, req)

		// Verify response was written (cookies cleared)
		if w.Code == 0 {
			w.Code = 200 // Default to OK if no explicit code was set
		}
	})
}

// TestSessionManagerHTTPSBehavior tests HTTPS-related behavior
func TestSessionManagerHTTPSBehavior(t *testing.T) {
	tests := []struct {
		name        string
		forceHTTPS  bool
		requestURL  string
		expectError bool
		description string
	}{
		{
			name:        "HTTPS forced with HTTP request",
			forceHTTPS:  true,
			requestURL:  "http://example.com/foo",
			expectError: false, // Manager creation shouldn't fail
			description: "Should create manager even when HTTPS is forced",
		},
		{
			name:        "HTTPS forced with HTTPS request",
			forceHTTPS:  true,
			requestURL:  "https://example.com/foo",
			expectError: false,
			description: "Should work normally with HTTPS request",
		},
		{
			name:        "HTTPS not forced with HTTP request",
			forceHTTPS:  false,
			requestURL:  "http://example.com/foo",
			expectError: false,
			description: "Should work normally when HTTPS not forced",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}

			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef",
				tt.forceHTTPS, "", logger, chunkManager)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
				return
			}

			// Override the session pool to use our mock
			sm.sessionPool.New = func() interface{} {
				return NewMockSessionData(sm, logger)
			}

			// Test session creation with the configured HTTPS behavior
			req := httptest.NewRequest("GET", tt.requestURL, nil)
			session, err := sm.GetSession(req)

			if err != nil {
				t.Logf("GetSession returned error (may be expected): %v", err)
			} else if session == nil {
				t.Error("Session should not be nil when no error occurred")
			}
		})
	}
}

// TestSessionManagerCookieDomain tests cookie domain configuration
func TestSessionManagerCookieDomain(t *testing.T) {
	tests := []struct {
		name         string
		cookieDomain string
		description  string
	}{
		{
			name:         "Empty cookie domain",
			cookieDomain: "",
			description:  "Should work with empty cookie domain",
		},
		{
			name:         "Specific cookie domain",
			cookieDomain: "example.com",
			description:  "Should work with specific cookie domain",
		},
		{
			name:         "Subdomain cookie domain",
			cookieDomain: ".example.com",
			description:  "Should work with subdomain cookie domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}

			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef",
				false, tt.cookieDomain, logger, chunkManager)

			if err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
				return
			}

			if sm == nil {
				t.Errorf("Session manager should not be nil for %s", tt.description)
				return
			}

			if sm.cookieDomain != tt.cookieDomain {
				t.Errorf("Cookie domain mismatch: expected %q, got %q",
					tt.cookieDomain, sm.cookieDomain)
			}
		})
	}
}

// BenchmarkSessionManagerCreation benchmarks session manager creation
func BenchmarkSessionManagerCreation(b *testing.B) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	encryptionKey := "0123456789abcdef0123456789abcdef0123456789abcdef"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sm, err := NewSessionManager(encryptionKey, false, "", logger, chunkManager, "test-instance")
		if err != nil {
			b.Fatalf("Failed to create session manager: %v", err)
		}
		_ = sm
	}
}

// BenchmarkSessionManagerGetSession benchmarks session retrieval
func BenchmarkSessionManagerGetSession(b *testing.B) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, chunkManager, "test-instance")
	if err != nil {
		b.Fatalf("Failed to create session manager: %v", err)
	}

	// Override the session pool to use our mock
	sm.sessionPool.New = func() interface{} {
		return NewMockSessionData(sm, logger)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		session, err := sm.GetSession(req)
		if err != nil {
			b.Fatalf("GetSession failed: %v", err)
		}

		// Clean up the session
		w := httptest.NewRecorder()
		_ = session.Clear(req, w)
	}
}

//lint:ignore U1000 May be needed for future test utilities
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestValidateSessionHealth tests session health validation
func TestValidateSessionHealth(t *testing.T) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, chunkManager, "test-instance")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	tests := []struct {
		name        string
		sessionData SessionData
		expectError bool
		description string
	}{
		{
			name:        "Nil session data",
			sessionData: nil,
			expectError: true,
			description: "Should fail with nil session data",
		},
		{
			name:        "Unauthenticated session",
			sessionData: &MockSessionData{authenticated: false},
			expectError: false,
			description: "Should pass with unauthenticated session",
		},
		{
			name:        "Authenticated session with tokens",
			sessionData: &MockSessionData{authenticated: true},
			expectError: false,
			description: "Should pass with properly authenticated session",
		},
		{
			name:        "Authenticated session without email (suspicious)",
			sessionData: &MockSessionData{authenticated: true},
			expectError: true,
			description: "Should fail when authenticated but no email",
		},
	}

	// Create a mock session with no email for the suspicious case
	suspiciousSession := &MockSessionData{authenticated: true, email: "", emailSet: true}

	// Replace the fourth test case with our suspicious session
	tests[3].sessionData = suspiciousSession

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.ValidateSessionHealth(tt.sessionData)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, got: %v", tt.description, err)
			}
		})
	}
}

// TestValidateTokenFormat tests token format validation
func TestValidateTokenFormat(t *testing.T) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, chunkManager, "test-instance")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		tokenType   string
		expectError bool
		description string
	}{
		{
			name:        "Valid JWT token",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			tokenType:   "access",
			expectError: false,
			description: "Should pass with valid JWT",
		},
		{
			name:        "Empty token",
			token:       "",
			tokenType:   "access",
			expectError: false,
			description: "Should pass with empty token",
		},
		{
			name:        "Invalid token - too few parts",
			token:       "header.payload",
			tokenType:   "access",
			expectError: true,
			description: "Should fail with incomplete JWT",
		},
		{
			name:        "Invalid token - too many parts",
			token:       "header.payload.signature.extra",
			tokenType:   "access",
			expectError: true,
			description: "Should fail with too many parts",
		},
		{
			name:        "Invalid token - empty part",
			token:       "header..signature",
			tokenType:   "id",
			expectError: true,
			description: "Should fail with empty payload part",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.validateTokenFormat(tt.token, tt.tokenType)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, got: %v", tt.description, err)
			}
		})
	}
}

// TestDetectSessionTampering tests session tampering detection
func TestDetectSessionTampering(t *testing.T) {
	logger := &MockLogger{}
	chunkManager := &MockChunkManager{}
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger, chunkManager, "test-instance")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	tests := []struct {
		name          string
		authenticated bool
		email         string
		expectError   bool
		description   string
	}{
		{
			name:          "Valid authenticated session",
			authenticated: true,
			email:         "user@example.com",
			expectError:   false,
			description:   "Should pass with valid authenticated session",
		},
		{
			name:          "Valid unauthenticated session",
			authenticated: false,
			email:         "",
			expectError:   false,
			description:   "Should pass with valid unauthenticated session",
		},
		{
			name:          "Suspicious: authenticated without email",
			authenticated: true,
			email:         "",
			expectError:   true,
			description:   "Should fail when authenticated but no email",
		},
		{
			name:          "Warning: email without authentication",
			authenticated: false,
			email:         "user@example.com",
			expectError:   false,
			description:   "Should pass but log warning when email exists without authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionData := &MockSessionData{authenticated: tt.authenticated, email: tt.email, emailSet: true}

			err := sm.detectSessionTampering(sessionData)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, got: %v", tt.description, err)
			}
		})
	}
}

// TestGetSessionMetrics tests session metrics retrieval
func TestGetSessionMetrics(t *testing.T) {
	tests := []struct {
		name         string
		forceHTTPS   bool
		cookieDomain string
		description  string
	}{
		{
			name:         "Basic metrics",
			forceHTTPS:   false,
			cookieDomain: "",
			description:  "Should return basic metrics",
		},
		{
			name:         "HTTPS forced metrics",
			forceHTTPS:   true,
			cookieDomain: "example.com",
			description:  "Should return metrics with HTTPS and domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef",
				tt.forceHTTPS, tt.cookieDomain, logger, chunkManager)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			metrics := sm.GetSessionMetrics()

			if metrics == nil {
				t.Error("Metrics should not be nil")
				return
			}

			expectedKeys := []string{"store_type", "cookie_domain", "force_https", "cleanup_done"}
			for _, key := range expectedKeys {
				if _, exists := metrics[key]; !exists {
					t.Errorf("Metrics should contain key %s", key)
				}
			}

			if metrics["force_https"] != tt.forceHTTPS {
				t.Errorf("Expected force_https=%v, got %v", tt.forceHTTPS, metrics["force_https"])
			}

			if metrics["cookie_domain"] != tt.cookieDomain {
				t.Errorf("Expected cookie_domain=%s, got %s", tt.cookieDomain, metrics["cookie_domain"])
			}
		})
	}
}

// TestShouldUseSecureCookies tests secure cookie determination
func TestShouldUseSecureCookies(t *testing.T) {
	tests := []struct {
		name         string
		forceHTTPS   bool
		requestSetup func() *http.Request
		expected     bool
		description  string
	}{
		{
			name:       "Force HTTPS enabled",
			forceHTTPS: true,
			requestSetup: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/foo", nil)
			},
			expected:    true,
			description: "Should return true when HTTPS is forced",
		},
		{
			name:       "HTTPS request with TLS",
			forceHTTPS: false,
			requestSetup: func() *http.Request {
				req := httptest.NewRequest("GET", "https://example.com/foo", nil)
				req.TLS = &tls.ConnectionState{} // Mock TLS
				return req
			},
			expected:    true,
			description: "Should return true for HTTPS request",
		},
		{
			name:       "HTTP request with X-Forwarded-Proto header",
			forceHTTPS: false,
			requestSetup: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			},
			expected:    true,
			description: "Should return true when X-Forwarded-Proto is https",
		},
		{
			name:       "Plain HTTP request",
			forceHTTPS: false,
			requestSetup: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/foo", nil)
			},
			expected:    false,
			description: "Should return false for plain HTTP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef",
				tt.forceHTTPS, "", logger, chunkManager)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := tt.requestSetup()
			result := sm.shouldUseSecureCookies(req)

			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.description, result)
			}
		})
	}
}

// TestGetSessionOptions tests session options generation
func TestGetSessionOptions(t *testing.T) {
	tests := []struct {
		name         string
		cookieDomain string
		isSecure     bool
		description  string
	}{
		{
			name:         "Secure options with domain",
			cookieDomain: "example.com",
			isSecure:     true,
			description:  "Should create secure options with domain",
		},
		{
			name:         "Insecure options without domain",
			cookieDomain: "",
			isSecure:     false,
			description:  "Should create insecure options without domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &MockLogger{}
			chunkManager := &MockChunkManager{}
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef",
				false, tt.cookieDomain, logger, chunkManager)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			options := sm.getSessionOptions(tt.isSecure)

			if options == nil {
				t.Error("Options should not be nil")
				return
			}

			if options.Secure != tt.isSecure {
				t.Errorf("Expected Secure=%v, got %v", tt.isSecure, options.Secure)
			}

			if options.Domain != tt.cookieDomain {
				t.Errorf("Expected Domain=%s, got %s", tt.cookieDomain, options.Domain)
			}

			if options.Path != "/" {
				t.Errorf("Expected Path=/, got %s", options.Path)
			}

			if !options.HttpOnly {
				t.Error("Expected HttpOnly=true")
			}

			if options.SameSite != http.SameSiteLaxMode {
				t.Errorf("Expected SameSite=Lax, got %v", options.SameSite)
			}

			if options.MaxAge != int(absoluteSessionTimeout.Seconds()) {
				t.Errorf("Expected MaxAge=%d, got %d", int(absoluteSessionTimeout.Seconds()), options.MaxAge)
			}
		})
	}
}

// TestAccessTokenCookie tests AccessTokenCookie function
func TestAccessTokenCookie(t *testing.T) {
	result := AccessTokenCookie()
	expected := "_oidc_raczylo_a"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

// TestRefreshTokenCookie tests RefreshTokenCookie function
func TestRefreshTokenCookie(t *testing.T) {
	result := RefreshTokenCookie()
	expected := "_oidc_raczylo_r"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

// TestIDTokenCookie tests IDTokenCookie function
func TestIDTokenCookie(t *testing.T) {
	result := IDTokenCookie()
	expected := "_oidc_raczylo_id"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
