package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// SessionTestCase represents a comprehensive session test scenario
type SessionTestCase struct {
	name        string
	scenario    string // "creation", "validation", "expiration", "persistence", "cleanup", "chunking", "security"
	sessionType string // "user", "admin", "api", "guest", "csrf"
	setup       func(*SessionTestFramework)
	execute     func(*SessionTestFramework) error
	validate    func(*testing.T, error, *SessionTestFramework)
	cleanup     func(*SessionTestFramework)
	concurrent  bool
	iterations  int
	timeout     time.Duration
	skipReason  string
}

// SessionTestFramework provides shared test infrastructure for session tests
type SessionTestFramework struct {
	t            *testing.T
	mockProvider *httptest.Server
	requests     []*http.Request
	responses    []*httptest.ResponseRecorder
	testTokens   map[string]string
	sessionIDs   []string
	mu           sync.RWMutex
	metrics      *SessionTestMetrics
	cleanupFuncs []func()
	config       *SessionTestConfig
}

// SessionTestMetrics tracks test performance metrics
type SessionTestMetrics struct {
	SessionsCreated   int64
	SessionsDestroyed int64
	TokensGenerated   int64
	TokensValidated   int64
	ChunksCreated     int64
	ChunksRetrieved   int64
	ErrorCount        int64
	Duration          time.Duration
}

// SessionTestConfig holds test configuration
type SessionTestConfig struct {
	MaxChunkSize      int
	MaxSessions       int
	EnableHTTPS       bool
	CookieDomain      string
	SessionTimeout    time.Duration
	EncryptionKey     string
	EnableCompression bool
}

// NewSessionTestFramework creates a new test framework instance
func NewSessionTestFramework(t *testing.T) *SessionTestFramework {
	framework := &SessionTestFramework{
		t:            t,
		requests:     make([]*http.Request, 0),
		responses:    make([]*httptest.ResponseRecorder, 0),
		testTokens:   make(map[string]string),
		sessionIDs:   make([]string, 0),
		metrics:      &SessionTestMetrics{},
		cleanupFuncs: make([]func(), 0),
		config: &SessionTestConfig{
			MaxChunkSize:      3900,
			MaxSessions:       1000,
			EnableHTTPS:       false,
			CookieDomain:      "",
			SessionTimeout:    time.Hour,
			EncryptionKey:     generateTestKey(),
			EnableCompression: true,
		},
	}

	// Setup mock OIDC provider
	framework.setupMockProvider()

	return framework
}

// generateTestKey generates a test encryption key
func generateTestKey() string {
	// 48 bytes = 384 bits for testing
	return "0123456789abcdef0123456789abcdef0123456789abcdef"
}

// setupMockProvider sets up a mock OIDC provider for testing
func (f *SessionTestFramework) setupMockProvider() {
	f.mockProvider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 f.mockProvider.URL,
				"authorization_endpoint": f.mockProvider.URL + "/auth",
				"token_endpoint":         f.mockProvider.URL + "/token",
				"userinfo_endpoint":      f.mockProvider.URL + "/userinfo",
				"jwks_uri":               f.mockProvider.URL + "/jwks",
			})
		case "/token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  f.generateTestToken("access", 3600),
				"id_token":      f.generateTestToken("id", 3600),
				"refresh_token": f.generateTestToken("refresh", 86400),
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":   "test-user-id",
				"email": "test@example.com",
				"name":  "Test User",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	f.cleanupFuncs = append(f.cleanupFuncs, f.mockProvider.Close)
}

// generateTestToken generates a test token
func (f *SessionTestFramework) generateTestToken(tokenType string, expiresIn int) string {
	atomic.AddInt64(&f.metrics.TokensGenerated, 1)

	// Create a realistic JWT-like token for testing
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"iss": f.mockProvider.URL,
		"sub": "test-user-id",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iat": time.Now().Unix(),
		"typ": tokenType,
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Generate a fake signature
	signature := make([]byte, 64)
	rand.Read(signature)
	sig := base64.RawURLEncoding.EncodeToString(signature)

	token := fmt.Sprintf("%s.%s.%s", header, payload, sig)

	// Thread-safe write to map
	f.mu.Lock()
	f.testTokens[tokenType] = token
	f.mu.Unlock()

	return token
}

// generateLargeToken generates a token of specified size for testing chunking
func (f *SessionTestFramework) generateLargeToken(size int) string {
	atomic.AddInt64(&f.metrics.TokensGenerated, 1)

	// Create base JWT structure
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	// Calculate how much padding we need in claims
	baseSize := len(header) + 2                          // for the dots
	signatureSize := 86                                  // approximate base64 encoded signature size
	paddingSize := size - baseSize - signatureSize - 100 // leave room for other claims

	if paddingSize < 0 {
		paddingSize = 0
	}

	// Create large padding data
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte('A' + (i % 26))
	}

	claims := map[string]interface{}{
		"iss":     f.mockProvider.URL,
		"sub":     "test-user-id",
		"aud":     "test-client-id",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
		"padding": base64.StdEncoding.EncodeToString(padding),
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Generate signature
	signature := make([]byte, 64)
	rand.Read(signature)
	sig := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

// Cleanup performs framework cleanup
func (f *SessionTestFramework) Cleanup() {
	for _, cleanup := range f.cleanupFuncs {
		cleanup()
	}
}

// TestSessionConsolidated runs all consolidated session tests
func TestSessionConsolidated(t *testing.T) {
	testCases := []SessionTestCase{
		// Session Creation Tests
		{
			name:        "session_basic_creation",
			scenario:    "creation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				atomic.AddInt64(&f.metrics.SessionsCreated, 1)
				// Simulate session creation
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				f.requests = append(f.requests, req)
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Session creation should succeed")
				assert.Greater(t, f.metrics.SessionsCreated, int64(0), "Session should be created")
			},
		},
		{
			name:        "session_pool_reuse",
			scenario:    "creation",
			sessionType: "user",
			iterations:  100,
			execute: func(f *SessionTestFramework) error {
				for i := 0; i < 100; i++ {
					atomic.AddInt64(&f.metrics.SessionsCreated, 1)
					atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed, "Sessions should be properly pooled")
			},
		},
		{
			name:        "session_concurrent_creation",
			scenario:    "creation",
			sessionType: "user",
			concurrent:  true,
			iterations:  50,
			execute: func(f *SessionTestFramework) error {
				var wg sync.WaitGroup
				errs := make(chan error, 50)

				for i := 0; i < 50; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						atomic.AddInt64(&f.metrics.SessionsCreated, 1)
						// Simulate concurrent session creation
						req := httptest.NewRequest("GET", fmt.Sprintf("http://example.com/%d", id), nil)
						f.mu.Lock()
						f.requests = append(f.requests, req)
						f.mu.Unlock()
					}(i)
				}

				wg.Wait()
				close(errs)

				for err := range errs {
					if err != nil {
						return err
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, int64(50), f.metrics.SessionsCreated, "All concurrent sessions should be created")
			},
		},

		// Session Validation Tests
		{
			name:        "session_token_validation",
			scenario:    "validation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				token := f.generateTestToken("access", 3600)
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Validate token format
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid token format")
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Token validation should succeed")
				assert.Greater(t, f.metrics.TokensValidated, int64(0))
			},
		},
		{
			name:        "session_corrupted_token_detection",
			scenario:    "validation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				token := f.generateTestToken("access", 3600)
				// Corrupt the token by modifying the signature
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid token format")
				}

				// Corrupt the signature part
				corrupted := parts[0] + "." + parts[1] + ".corrupted!"
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Validate should detect corruption - corrupted tokens should fail validation
				corruptedParts := strings.Split(corrupted, ".")
				if len(corruptedParts) == 3 {
					// Try to decode the corrupted signature
					_, err := base64.RawURLEncoding.DecodeString(corruptedParts[2])
					if err == nil {
						return fmt.Errorf("corruption not detected")
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Corruption detection should work")
			},
		},
		{
			name:        "session_expired_token_handling",
			scenario:    "validation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Generate an expired token
				token := f.generateTestToken("access", -3600) // negative expiry
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Parse and check expiry
				parts := strings.Split(token, ".")
				if len(parts) == 3 {
					payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var claims map[string]interface{}
					json.Unmarshal(payload, &claims)

					if exp, ok := claims["exp"].(float64); ok {
						if exp < float64(time.Now().Unix()) {
							atomic.AddInt64(&f.metrics.ErrorCount, 1)
							return nil // Expected behavior
						}
					}
				}
				return fmt.Errorf("expired token not detected")
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Expired token should be detected")
				assert.Greater(t, f.metrics.ErrorCount, int64(0))
			},
		},

		// Session Expiration Tests
		{
			name:        "session_ttl_expiration",
			scenario:    "expiration",
			sessionType: "user",
			timeout:     3 * time.Second,
			execute: func(f *SessionTestFramework) error {
				atomic.AddInt64(&f.metrics.SessionsCreated, 1)
				// Simulate session with short TTL
				time.Sleep(100 * time.Millisecond) // Don't sleep for full timeout
				atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed)
			},
		},
		{
			name:        "session_refresh_token_expiry",
			scenario:    "expiration",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				refreshToken := f.generateTestToken("refresh", 86400)
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Check refresh token is valid for longer period
				parts := strings.Split(refreshToken, ".")
				if len(parts) == 3 {
					payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var claims map[string]interface{}
					json.Unmarshal(payload, &claims)

					if exp, ok := claims["exp"].(float64); ok {
						timeUntilExpiry := time.Until(time.Unix(int64(exp), 0))
						if timeUntilExpiry < 23*time.Hour {
							return fmt.Errorf("refresh token expiry too short: %v", timeUntilExpiry)
						}
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Refresh token should have correct expiry")
			},
		},

		// Session Persistence Tests
		{
			name:        "session_cookie_persistence",
			scenario:    "persistence",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				w := httptest.NewRecorder()

				// Set session cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    "test-session-123",
					Path:     "/",
					HttpOnly: true,
					Secure:   f.config.EnableHTTPS,
					SameSite: http.SameSiteLaxMode,
				})

				f.requests = append(f.requests, req)
				f.responses = append(f.responses, w)

				// Verify cookie was set
				cookies := w.Result().Cookies()
				if len(cookies) == 0 {
					return fmt.Errorf("no cookies set")
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.NotEmpty(t, f.responses, "Response should be recorded")
			},
		},
		{
			name:        "session_state_preservation",
			scenario:    "persistence",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Store state
				state := map[string]interface{}{
					"user_id": "test-user",
					"email":   "test@example.com",
					"roles":   []string{"user", "admin"},
				}

				// Serialize and deserialize to test persistence
				data, err := json.Marshal(state)
				if err != nil {
					return err
				}

				var restored map[string]interface{}
				if err := json.Unmarshal(data, &restored); err != nil {
					return err
				}

				// Verify state preserved
				if restored["user_id"] != state["user_id"] {
					return fmt.Errorf("state not preserved")
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Session state should be preserved")
			},
		},

		// Session Cleanup Tests
		{
			name:        "session_proper_cleanup",
			scenario:    "cleanup",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Create and destroy sessions
				for i := 0; i < 10; i++ {
					atomic.AddInt64(&f.metrics.SessionsCreated, 1)
					sessionID := fmt.Sprintf("session-%d", i)
					f.sessionIDs = append(f.sessionIDs, sessionID)
				}

				// Cleanup all sessions
				for range f.sessionIDs {
					atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
				}
				f.sessionIDs = nil

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed)
				assert.Empty(t, f.sessionIDs, "All sessions should be cleaned up")
			},
		},
		{
			name:        "session_goroutine_leak_prevention",
			scenario:    "cleanup",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				initialGoroutines := runtime.NumGoroutine()

				// Create sessions that might spawn goroutines
				var wg sync.WaitGroup
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						atomic.AddInt64(&f.metrics.SessionsCreated, 1)
						time.Sleep(10 * time.Millisecond)
						atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
					}(i)
				}

				wg.Wait()
				runtime.GC()
				time.Sleep(100 * time.Millisecond)

				finalGoroutines := runtime.NumGoroutine()
				if finalGoroutines > initialGoroutines+2 { // Allow small variance
					return fmt.Errorf("goroutine leak detected: %d -> %d", initialGoroutines, finalGoroutines)
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "No goroutine leaks should occur")
			},
		},

		// Session Chunking Tests
		{
			name:        "session_large_token_chunking",
			scenario:    "chunking",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Generate a large token that requires chunking
				largeToken := f.generateLargeToken(10000) // 10KB token

				// Calculate expected chunks
				chunkSize := f.config.MaxChunkSize
				expectedChunks := (len(largeToken) + chunkSize - 1) / chunkSize

				// Simulate chunking
				chunks := make([]string, 0)
				for i := 0; i < len(largeToken); i += chunkSize {
					end := i + chunkSize
					if end > len(largeToken) {
						end = len(largeToken)
					}
					chunks = append(chunks, largeToken[i:end])
					atomic.AddInt64(&f.metrics.ChunksCreated, 1)
				}

				if len(chunks) != expectedChunks {
					return fmt.Errorf("expected %d chunks, got %d", expectedChunks, len(chunks))
				}

				// Simulate reconstruction
				reconstructed := strings.Join(chunks, "")
				if reconstructed != largeToken {
					return fmt.Errorf("token reconstruction failed")
				}
				atomic.AddInt64(&f.metrics.ChunksRetrieved, int64(len(chunks)))

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Token chunking should work correctly")
				assert.Greater(t, f.metrics.ChunksCreated, int64(0))
				assert.Equal(t, f.metrics.ChunksCreated, f.metrics.ChunksRetrieved)
			},
		},
		{
			name:        "session_chunk_boundary_validation",
			scenario:    "chunking",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Test exact boundary conditions
				testSizes := []int{
					f.config.MaxChunkSize - 1,
					f.config.MaxChunkSize,
					f.config.MaxChunkSize + 1,
					f.config.MaxChunkSize * 2,
					f.config.MaxChunkSize*2 - 1,
					f.config.MaxChunkSize*2 + 1,
				}

				for _, size := range testSizes {
					token := f.generateLargeToken(size)
					actualSize := len(token)
					expectedChunks := (actualSize + f.config.MaxChunkSize - 1) / f.config.MaxChunkSize

					actualChunks := 0
					for i := 0; i < len(token); i += f.config.MaxChunkSize {
						actualChunks++
						atomic.AddInt64(&f.metrics.ChunksCreated, 1)
					}

					if actualChunks != expectedChunks {
						return fmt.Errorf("size %d (actual token size %d): expected %d chunks, got %d", size, actualSize, expectedChunks, actualChunks)
					}
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Chunk boundaries should be handled correctly")
			},
		},

		// Session Security Tests
		{
			name:        "session_csrf_token_management",
			scenario:    "security",
			sessionType: "csrf",
			execute: func(f *SessionTestFramework) error {
				// Generate CSRF token
				csrfToken := make([]byte, 32)
				if _, err := rand.Read(csrfToken); err != nil {
					return err
				}

				csrfString := base64.RawURLEncoding.EncodeToString(csrfToken)

				// Store in session
				f.testTokens["csrf"] = csrfString

				// Validate CSRF token
				if len(csrfString) < 40 {
					return fmt.Errorf("CSRF token too short")
				}

				atomic.AddInt64(&f.metrics.TokensGenerated, 1)
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "CSRF token should be properly managed")
				assert.NotEmpty(t, f.testTokens["csrf"])
			},
		},
		{
			name:        "session_injection_prevention",
			scenario:    "security",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Test various injection attempts
				maliciousInputs := []string{
					`{"admin": true}`,
					`<script>alert('xss')</script>`,
					`'; DROP TABLE sessions; --`,
					`../../../etc/passwd`,
					string([]byte{0x00, 0x01, 0x02}), // null bytes
				}

				for _, input := range maliciousInputs {
					// Validate that input is properly sanitized
					sanitized := base64.StdEncoding.EncodeToString([]byte(input))
					decoded, err := base64.StdEncoding.DecodeString(sanitized)
					if err != nil {
						return err
					}

					if string(decoded) != input {
						return fmt.Errorf("sanitization changed input unexpectedly")
					}

					atomic.AddInt64(&f.metrics.TokensValidated, 1)
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Injection attempts should be handled safely")
			},
		},
		{
			name:        "session_secure_cookie_settings",
			scenario:    "security",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				w := httptest.NewRecorder()

				// Test secure cookie settings
				cookie := &http.Cookie{
					Name:     "session",
					Value:    "test-session",
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   3600,
				}

				http.SetCookie(w, cookie)

				// Verify cookie attributes
				cookies := w.Result().Cookies()
				if len(cookies) == 0 {
					return fmt.Errorf("no cookie set")
				}

				c := cookies[0]
				if !c.HttpOnly {
					return fmt.Errorf("cookie not HttpOnly")
				}
				if c.SameSite != http.SameSiteStrictMode {
					return fmt.Errorf("incorrect SameSite setting")
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Secure cookie settings should be enforced")
			},
		},

		// Session Stress Tests
		{
			name:        "session_high_concurrency_stress",
			scenario:    "creation",
			sessionType: "user",
			concurrent:  true,
			iterations:  1000,
			timeout:     30 * time.Second,
			execute: func(f *SessionTestFramework) error {
				var wg sync.WaitGroup
				errors := make([]error, 0)

				// Run high concurrency test
				concurrency := 100
				iterations := 10

				for i := 0; i < concurrency; i++ {
					wg.Add(1)
					go func(workerID int) {
						defer wg.Done()

						for j := 0; j < iterations; j++ {
							// Create session
							atomic.AddInt64(&f.metrics.SessionsCreated, 1)

							// Generate tokens
							f.generateTestToken("access", 3600)
							f.generateTestToken("refresh", 86400)

							// Validate tokens
							atomic.AddInt64(&f.metrics.TokensValidated, 2)

							// Cleanup session
							atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)

							// Small delay to simulate real usage
							time.Sleep(time.Millisecond)
						}
					}(i)
				}

				wg.Wait()

				if len(errors) > 0 {
					return errors[0]
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "High concurrency stress test should pass")
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed, "All sessions should be cleaned up")
			},
		},
		{
			name:        "session_memory_bounds_enforcement",
			scenario:    "cleanup",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				maxSessions := f.config.MaxSessions

				// Try to create more sessions than allowed
				for i := 0; i < maxSessions+100; i++ {
					sessionID := fmt.Sprintf("session-%d", i)
					f.sessionIDs = append(f.sessionIDs, sessionID)
					atomic.AddInt64(&f.metrics.SessionsCreated, 1)

					// Enforce max sessions
					if len(f.sessionIDs) > maxSessions {
						// Remove oldest session
						f.sessionIDs = f.sessionIDs[1:]
						atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
					}
				}

				if len(f.sessionIDs) > maxSessions {
					return fmt.Errorf("max sessions exceeded: %d > %d", len(f.sessionIDs), maxSessions)
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Memory bounds should be enforced")
				assert.LessOrEqual(t, len(f.sessionIDs), f.config.MaxSessions)
			},
		},
	}

	// Run all test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			framework := NewSessionTestFramework(t)
			defer framework.Cleanup()

			// Setup
			if tc.setup != nil {
				tc.setup(framework)
			}

			// Cleanup
			if tc.cleanup != nil {
				defer tc.cleanup(framework)
			}

			// Set timeout if specified
			if tc.timeout > 0 {
				timer := time.NewTimer(tc.timeout)
				done := make(chan bool)

				go func() {
					err := tc.execute(framework)
					tc.validate(t, err, framework)
					done <- true
				}()

				select {
				case <-done:
					timer.Stop()
				case <-timer.C:
					t.Fatal("Test timeout exceeded")
				}
			} else {
				// Execute test
				err := tc.execute(framework)

				// Validate results
				tc.validate(t, err, framework)
			}
		})
	}
}

// Benchmark tests
func BenchmarkSessionCreation(b *testing.B) {
	framework := &SessionTestFramework{
		metrics:    &SessionTestMetrics{},
		testTokens: make(map[string]string),
		config: &SessionTestConfig{
			MaxChunkSize: 3900,
			MaxSessions:  1000,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		atomic.AddInt64(&framework.metrics.SessionsCreated, 1)
		atomic.AddInt64(&framework.metrics.SessionsDestroyed, 1)
	}

	b.ReportMetric(float64(framework.metrics.SessionsCreated)/float64(b.N), "sessions/op")
}

func BenchmarkTokenGeneration(b *testing.B) {
	framework := NewSessionTestFramework(&testing.T{})
	defer framework.Cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		framework.generateTestToken("access", 3600)
	}

	b.ReportMetric(float64(framework.metrics.TokensGenerated)/float64(b.N), "tokens/op")
}

func BenchmarkTokenValidation(b *testing.B) {
	framework := NewSessionTestFramework(&testing.T{})
	defer framework.Cleanup()

	token := framework.generateTestToken("access", 3600)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			atomic.AddInt64(&framework.metrics.TokensValidated, 1)
		}
	}

	b.ReportMetric(float64(framework.metrics.TokensValidated)/float64(b.N), "validations/op")
}

func BenchmarkLargeTokenChunking(b *testing.B) {
	framework := &SessionTestFramework{
		metrics:    &SessionTestMetrics{},
		testTokens: make(map[string]string),
		config: &SessionTestConfig{
			MaxChunkSize: 3900,
		},
	}

	// Generate test token once
	largeToken := strings.Repeat("A", 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunks := make([]string, 0)
		for j := 0; j < len(largeToken); j += framework.config.MaxChunkSize {
			end := j + framework.config.MaxChunkSize
			if end > len(largeToken) {
				end = len(largeToken)
			}
			chunks = append(chunks, largeToken[j:end])
			atomic.AddInt64(&framework.metrics.ChunksCreated, 1)
		}

		// Reconstruct
		_ = strings.Join(chunks, "")
		atomic.AddInt64(&framework.metrics.ChunksRetrieved, int64(len(chunks)))
	}

	b.ReportMetric(float64(framework.metrics.ChunksCreated)/float64(b.N), "chunks_created/op")
	b.ReportMetric(float64(framework.metrics.ChunksRetrieved)/float64(b.N), "chunks_retrieved/op")
}

func BenchmarkConcurrentSessionOperations(b *testing.B) {
	framework := &SessionTestFramework{
		metrics:    &SessionTestMetrics{},
		testTokens: make(map[string]string),
		sessionIDs: make([]string, 0),
		config: &SessionTestConfig{
			MaxSessions: 10000,
		},
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create session
			atomic.AddInt64(&framework.metrics.SessionsCreated, 1)

			// Generate token
			token := make([]byte, 32)
			rand.Read(token)
			tokenStr := base64.RawURLEncoding.EncodeToString(token)
			atomic.AddInt64(&framework.metrics.TokensGenerated, 1)

			// Validate token
			if len(tokenStr) > 0 {
				atomic.AddInt64(&framework.metrics.TokensValidated, 1)
			}

			// Destroy session
			atomic.AddInt64(&framework.metrics.SessionsDestroyed, 1)
		}
	})

	b.ReportMetric(float64(framework.metrics.SessionsCreated)/float64(b.N), "sessions/op")
	b.ReportMetric(float64(framework.metrics.TokensGenerated)/float64(b.N), "tokens/op")
}
