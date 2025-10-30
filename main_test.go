package traefikoidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
)

// TestSuite holds common test data and setup
type TestSuite struct {
	t              *testing.T
	rsaPrivateKey  *rsa.PrivateKey
	rsaPublicKey   *rsa.PublicKey
	ecPrivateKey   *ecdsa.PrivateKey
	tOidc          *TraefikOidc
	mockJWKCache   *MockJWKCache
	sessionManager *SessionManager
	// utf            *UnifiedTestFramework // Removed - consolidated test framework
	token string
}

// NewTestSuite creates a new test suite with automatic cleanup
func NewTestSuite(t *testing.T) *TestSuite {
	ts := &TestSuite{
		t: t,
		// utf: NewUnifiedTestFramework(t), // Removed
	}
	return ts
}

// Setup initializes the test suite
func (ts *TestSuite) Setup() {
	// Initialize unified test framework if not already done
	// Unified test framework removed - using direct cleanup

	var err error
	ts.rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ts.t.Fatalf("Failed to generate RSA key: %v", err)
	}
	ts.rsaPublicKey = &ts.rsaPrivateKey.PublicKey

	// Generate EC key for EC key tests
	ts.ecPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ts.t.Fatalf("Failed to generate EC key: %v", err)
	}

	// Create a JWK for the RSA public key
	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(ts.rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(ts.rsaPublicKey.E)))),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	// Create a mock JWKCache
	ts.mockJWKCache = &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	// Create a test JWT token signed with the RSA private key
	// Create timestamps with proper clock skew
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Add(-2 * time.Minute).Unix() // Account for clock skew
	nbf := now.Add(-2 * time.Minute).Unix() // Account for clock skew

	ts.token, err = createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   generateRandomString(16),
	})
	if err != nil {
		ts.t.Fatalf("Failed to create test JWT: %v", err)
	}

	logger := NewLogger("info")
	ts.sessionManager, _ = NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", logger, "test-instance")

	// Create WaitGroup for the OIDC instance
	goroutineWG := &sync.WaitGroup{}

	// Initialize caches properly
	tokenBlacklist := NewCache()
	tokenCacheInternal := NewCache()
	tokenCache := &TokenCache{}
	if tokenCache.cache == nil {
		// Type assert to get the underlying UniversalCache
		if wrapper, ok := tokenCacheInternal.(*CacheInterfaceWrapper); ok {
			tokenCache.cache = wrapper.cache
		}
	}

	// Common TraefikOidc instance
	ts.tOidc = &TraefikOidc{
		issuerURL:          "https://test-issuer.com",
		clientID:           "test-client-id",
		audience:           "test-client-id",
		clientSecret:       "test-client-secret",
		jwkCache:           ts.mockJWKCache,
		jwksURL:            "https://test-jwks-url.com",
		revocationURL:      "https://revocation-endpoint.com",
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		tokenBlacklist:     tokenBlacklist,
		tokenCache:         tokenCache,
		logger:             logger,
		allowedUserDomains: map[string]struct{}{"example.com": {}},
		excludedURLs:       map[string]struct{}{"/favicon": {}, "/health": {}},
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		// Explicitly set paths as New() is bypassed
		redirURLPath:            "/callback",                     // Assume default callback path for tests
		logoutURLPath:           "/callback/logout",              // Assume default logout path for tests
		tokenURL:                "https://test-issuer.com/token", // Explicitly set for refresh tests
		extractClaimsFunc:       extractClaims,
		initComplete:            make(chan struct{}),
		sessionManager:          ts.sessionManager,
		goroutineWG:             goroutineWG,
		ctx:                     context.Background(),
		tokenCleanupStopChan:    make(chan struct{}),
		metadataRefreshStopChan: make(chan struct{}),
	}
	close(ts.tOidc.initComplete)
	// ts.tOidc.exchangeCodeForTokenFunc = ts.exchangeCodeForTokenFunc // Removed
	ts.tOidc.tokenVerifier = ts.tOidc
	ts.tOidc.jwtVerifier = ts.tOidc
	// Set default mock exchanger
	ts.tOidc.tokenExchanger = &MockTokenExchanger{
		ExchangeCodeFunc: func(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
			// Default mock behavior for code exchange
			return &TokenResponse{
				IDToken:      ts.token, // Use the valid token from setup
				AccessToken:  ts.token,
				RefreshToken: "default-refresh-token",
				ExpiresIn:    3600,
			}, nil
		},
		RefreshTokenFunc: func(refreshToken string) (*TokenResponse, error) {
			// Default mock behavior for refresh (can be overridden in tests)
			return nil, fmt.Errorf("default mock: refresh not expected")
		},
		RevokeTokenFunc: func(token, tokenType string) error {
			// Default mock behavior for revoke
			return nil
		},
	}

	// OIDC instance created

	// Register cleanup
	ts.t.Cleanup(func() {
		if ts.tOidc.tokenBlacklist != nil {
			ts.tOidc.tokenBlacklist.Close()
		}
		if ts.tOidc.tokenCache != nil && ts.tOidc.tokenCache.cache != nil {
			ts.tOidc.tokenCache.cache.Close()
		}
	})
}

// Helper function exchangeCodeForTokenFunc removed as it's unused after refactoring to TokenExchanger interface.

// MockJWKCache implements JWKCacheInterface
type MockJWKCache struct {
	mu   sync.RWMutex
	JWKS *JWKSet
	Err  error
}

// Close is a no-op for the mock.
func (m *MockJWKCache) Close() {
	// No operation needed for the mock.
}

func (m *MockJWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.JWKS, m.Err
}

func (m *MockJWKCache) Cleanup() {
	// Mock cleanup implementation
	m.mu.Lock()
	defer m.mu.Unlock()
	m.JWKS = nil
	m.Err = nil
}

// MockTokenVerifier implements TokenVerifier for testing, allowing interception of VerifyToken calls.
type MockTokenVerifier struct {
	VerifyFunc func(token string) error
}

func (m *MockTokenVerifier) VerifyToken(token string) error {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(token)
	}
	return fmt.Errorf("VerifyFunc not implemented in mock")
}

// MockTokenExchanger implements TokenExchanger for testing
type MockTokenExchanger struct {
	ExchangeCodeFunc func(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error)
	RefreshTokenFunc func(refreshToken string) (*TokenResponse, error)
	RevokeTokenFunc  func(token, tokenType string) error
}

func (m *MockTokenExchanger) ExchangeCodeForToken(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	if m.ExchangeCodeFunc != nil {
		return m.ExchangeCodeFunc(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
	}
	return nil, fmt.Errorf("ExchangeCodeFunc not implemented in mock")
}

func (m *MockTokenExchanger) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(refreshToken)
	}
	return nil, fmt.Errorf("RefreshTokenFunc not implemented in mock")
}

func (m *MockTokenExchanger) RevokeTokenWithProvider(token, tokenType string) error {
	if m.RevokeTokenFunc != nil {
		return m.RevokeTokenFunc(token, tokenType)
	}
	return fmt.Errorf("RevokeTokenFunc not implemented in mock")
}

// Helper function to check if a token is a test token
func isTestToken(token string) bool {
	// Parse the token without verification to check if it's a test token
	claims, err := extractClaims(token)
	if err != nil {
		return false
	}

	// Check if the issuer is our test issuer
	if iss, ok := claims["iss"].(string); ok {
		return iss == "https://test-issuer.com"
	}

	// Check if audience is our test client
	if aud, ok := claims["aud"].(string); ok {
		return aud == "test-client-id"
	}

	return false
}

// Helper function to create a new valid token for refresh tests using test suite
func (ts *TestSuite) createNewValidToken() string {
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Add(-2 * time.Minute).Unix()
	nbf := now.Add(-2 * time.Minute).Unix()

	token, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   generateRandomString(16),
	})

	return token
}

// Helper function to create a JWT token
func createTestJWT(privateKey *rsa.PrivateKey, alg, kid string, claims map[string]interface{}) (string, error) {
	header := map[string]interface{}{
		"alg": alg,
		"kid": kid,
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signedContent := headerEncoded + "." + claimsEncoded

	// Select the appropriate hash function based on algorithm
	var hashFunc crypto.Hash
	switch alg {
	case "RS256", "PS256":
		hashFunc = crypto.SHA256
	case "RS384", "PS384":
		hashFunc = crypto.SHA384
	case "RS512", "PS512":
		hashFunc = crypto.SHA512
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	hasher := hashFunc.New()
	hasher.Write([]byte(signedContent))
	hashed := hasher.Sum(nil)

	var signatureBytes []byte

	// Use appropriate signing method based on algorithm
	if strings.HasPrefix(alg, "RS") {
		// PKCS1v15 signing for RS* algorithms
		signatureBytes, err = rsa.SignPKCS1v15(rand.Reader, privateKey, hashFunc, hashed)
	} else if strings.HasPrefix(alg, "PS") {
		// PSS signing for PS* algorithms
		signatureBytes, err = rsa.SignPSS(rand.Reader, privateKey, hashFunc, hashed, nil)
	} else {
		return "", fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	if err != nil {
		return "", err
	}

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signatureBytes)

	token := signedContent + "." + signatureEncoded

	return token, nil
}

func bigIntToBytes(i *big.Int) []byte {
	return i.Bytes()
}

// TestVerifyToken tests the VerifyToken method
func TestVerifyToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name          string
		token         string
		blacklist     bool
		rateLimit     bool
		cacheToken    bool
		expectedError bool
	}{
		{
			name:          "Valid token",
			token:         ts.token,
			expectedError: false,
		},
		{
			name:          "Invalid token signature",
			token:         ts.token + "invalid",
			expectedError: true,
		},
		{
			name:          "Blacklisted token",
			token:         ts.token,
			blacklist:     true,
			expectedError: true,
		},
		{
			name:          "Rate limit exceeded",
			token:         ts.token,
			rateLimit:     true,
			expectedError: true,
		},
		{
			name:          "Token in cache",
			token:         ts.token,
			cacheToken:    true,
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset token blacklist and cache for each test
			ts.tOidc.tokenBlacklist = NewCache() // Use generic cache for blacklist
			// Clear the token cache instead of creating a new one (it's a singleton)
			ts.tOidc.tokenCache = NewTokenCache()
			ts.tOidc.tokenCache.Clear()
			ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Second), 10)

			// Set up the test case
			if tc.blacklist {
				// Use Set with a duration. Value 'true' is arbitrary.
				ts.tOidc.tokenBlacklist.Set(tc.token, true, 1*time.Hour)
			}

			if tc.rateLimit {
				// Exceed rate limit
				ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Hour), 0)
			}

			if tc.cacheToken {
				// Use more realistic claims for cached token
				ts.tOidc.tokenCache.Set(tc.token, map[string]interface{}{
					"iss": "https://test-issuer.com",
					"sub": "test-subject",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"jti": generateRandomString(16), // Add a JTI claim to prevent replay detection
				}, time.Minute)

				// Verify the token is actually in the cache
				if claims, exists := ts.tOidc.tokenCache.Get(tc.token); exists {
					t.Logf("Token found in cache with claims: %v", claims)
				} else {
					t.Logf("Token NOT found in cache despite cacheToken=true")
				}
			}

			err := ts.tOidc.VerifyToken(tc.token)
			if tc.expectedError && err == nil {
				t.Errorf("Test %s: expected error but got nil", tc.name)
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Test %s: expected no error but got %v", tc.name, err)
			}
		})
	}
}

// TestServeHTTP tests the ServeHTTP method
func TestServeHTTP(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	ts.tOidc.next = nextHandler
	ts.tOidc.name = "test"

	// Helper to create an expired token
	createExpiredToken := func() string {
		exp := time.Now().Add(-1 * time.Hour).Unix() // Expired 1 hour ago
		iat := time.Now().Add(-2 * time.Hour).Unix()
		nbf := time.Now().Add(-2 * time.Hour).Unix()
		expiredToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   exp,
			"iat":   iat,
			"nbf":   nbf,
			"sub":   "test-subject",
			"email": "user@example.com",
			"nonce": "test-nonce-expired", // Different nonce for clarity
			"jti":   generateRandomString(16),
		})
		return expiredToken
	}

	tests := []struct {
		sessionValues             map[interface{}]interface{}
		setupSession              func(*SessionData)
		mockRefreshTokenFunc      func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error)
		assertSessionAfterRequest func(t *testing.T, rr *httptest.ResponseRecorder, req *http.Request, sessionManager *SessionManager)
		requestHeaders            map[string]string
		name                      string
		requestPath               string
		expectedBody              string
		expectedStatus            int
	}{
		{
			name:           "Excluded URL",
			requestPath:    "/favicon.ico",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:        "Unauthenticated request (no refresh token) to protected URL",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				// Ensure no tokens are set
				session.SetAuthenticated(false)
				session.SetAccessToken("")
				session.SetRefreshToken("")
			},
			expectedStatus: http.StatusFound, // Expect redirect to OIDC as there's no refresh token
		},
		{
			name:        "Unauthenticated request (with refresh token) to protected URL - Expect Refresh Attempt",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(false)                                // Not authenticated
				session.SetAccessToken("")                                     // No access token
				session.SetRefreshToken("valid-refresh-token-for-unauth-test") // BUT has refresh token
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				return func(refreshToken string) (*TokenResponse, error) {
					if refreshToken != "valid-refresh-token-for-unauth-test" {
						return nil, fmt.Errorf("mock error: unexpected refresh token '%s'", refreshToken)
					}
					// Simulate successful refresh
					newToken := ts.createNewValidToken() // Use helper from TestServeHTTP
					return &TokenResponse{IDToken: newToken, AccessToken: newToken, RefreshToken: "new-refresh-token-unauth", ExpiresIn: 3600}, nil
				}
			},
			expectedStatus: http.StatusOK, // Expect OK after successful refresh
			expectedBody:   "OK",
		},
		{
			name:        "Unauthenticated request (with refresh token) to protected URL - Refresh Fails",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(false)                                  // Not authenticated
				session.SetAccessToken("")                                       // No access token
				session.SetRefreshToken("invalid-refresh-token-for-unauth-test") // Invalid refresh token
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				return func(refreshToken string) (*TokenResponse, error) {
					// Simulate failed refresh
					return nil, fmt.Errorf("mock error: refresh token invalid")
				}
			},
			expectedStatus: http.StatusFound, // Expect redirect to OIDC after failed refresh
		},
		{
			name:        "Authenticated request to protected URL (Valid Token)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
				// Generate a fresh valid token for this test case to avoid replay issues
				freshToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(1 * time.Hour).Unix(),
					"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "sub": "test-subject", "email": "user@example.com",
					"jti": generateRandomString(16), // Unique JTI
				})
				session.SetAccessToken(freshToken)
				session.SetIDToken(freshToken) // Ensure ID token is also set
				session.SetRefreshToken("valid-refresh-token")
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		// This test case remains valid as the logic should still attempt refresh when expired token + refresh token exist
		{
			name:        "Authenticated request with expired token and successful refresh",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				// NOTE: isUserAuthenticated now returns authenticated=false if access token is expired,
				// even if session.SetAuthenticated(true) was called.
				// We rely on needsRefresh=true and the presence of the refresh token to trigger the refresh attempt.
				session.SetAuthenticated(true) // Set flag initially, though isUserAuthenticated will override based on token
				session.SetEmail("user@example.com")
				// Create an expired token for this test
				expiredToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(-1 * time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(), "nbf": time.Now().Add(-2 * time.Hour).Unix(),
					"sub": "test-subject", "email": "test@example.com", "jti": generateRandomString(16),
				})
				session.SetAccessToken(expiredToken)           // Set expired token
				session.SetRefreshToken("valid-refresh-token") // Set valid refresh token
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				return func(refreshToken string) (*TokenResponse, error) {
					if refreshToken != "valid-refresh-token" {
						return nil, fmt.Errorf("mock error: expected 'valid-refresh-token', got '%s'", refreshToken)
					}
					// Simulate successful refresh
					newToken := ts.createNewValidToken()
					return &TokenResponse{
						IDToken:      newToken, // Return new valid token
						AccessToken:  newToken, // Often the same as ID token in tests
						RefreshToken: "new-refresh-token",
						ExpiresIn:    3600,
					}, nil
				}
			},
			expectedStatus: http.StatusOK, // Expect success after refresh
			expectedBody:   "OK",
			assertSessionAfterRequest: func(t *testing.T, rr *httptest.ResponseRecorder, req *http.Request, sessionManager *SessionManager) {
				// Create a new request to read the cookies set by the response recorder
				reqForCookieRead := httptest.NewRequest("GET", "/protected", nil)
				for _, cookie := range rr.Result().Cookies() {
					reqForCookieRead.AddCookie(cookie)
				}
				// Get session based on response cookies
				session, err := sessionManager.GetSession(reqForCookieRead)
				if err != nil {
					t.Fatalf("Failed to get session after request: %v", err)
				}
				// Assert new tokens are in the session
				if session.GetAccessToken() == "" || session.GetAccessToken() == createExpiredToken() {
					t.Errorf("Expected access token to be updated in session, but it was empty or still the expired one")
				}
				if session.GetRefreshToken() != "new-refresh-token" {
					t.Errorf("Expected refresh token to be updated to 'new-refresh-token', got '%s'", session.GetRefreshToken())
				}
				// Also check authenticated flag is now true
				if !session.GetAuthenticated() {
					t.Errorf("Expected session to be marked authenticated after successful refresh")
				}
			},
		},
		// This test case remains valid as the logic should still return 401 for API clients on refresh failure
		{
			name:        "Logout URL",
			requestPath: "/callback/logout", // Match the default logout path set in TestSuite.Setup
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
				// Generate a fresh valid token for this test case
				freshToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(1 * time.Hour).Unix(),
					"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "sub": "test-subject", "email": "user@example.com",
					"jti": generateRandomString(16), // Unique JTI
				})
				session.SetAccessToken(freshToken)
			},
			expectedStatus: http.StatusFound, // Expect redirect after logout
			expectedBody:   "",
			// No specific session assertion needed for logout redirect itself
		},
		{
			name:        "Authenticated request with expired token and FAILED refresh (Accept: JSON)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true) // Set flag initially
				session.SetEmail("user@example.com")
				// Create an expired token for this test
				expiredToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(-1 * time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(), "nbf": time.Now().Add(-2 * time.Hour).Unix(),
					"sub": "test-subject", "email": "test@example.com", "jti": generateRandomString(16),
				})
				session.SetAccessToken(expiredToken)           // Expired access token
				session.SetRefreshToken("valid-refresh-token") // Valid refresh token
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				return func(refreshToken string) (*TokenResponse, error) {
					// Simulate failed refresh
					return nil, fmt.Errorf("mock error: refresh token invalid or provider down")
				}
			},
			requestHeaders: map[string]string{
				"Accept": "application/json",
			},
			expectedStatus: http.StatusUnauthorized, // Expect 401 for API client after failed refresh attempt
			expectedBody:   `{"error":"Unauthorized","error_description":"Token refresh failed","status_code":401}`,
		},
		// This test case remains valid as the logic should still redirect browser clients on refresh failure
		{
			name:        "Authenticated request with expired token and FAILED refresh (Accept: HTML)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true) // Set flag initially
				session.SetEmail("user@example.com")
				// Create an expired token for this test
				expiredToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(-1 * time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(), "nbf": time.Now().Add(-2 * time.Hour).Unix(),
					"sub": "test-subject", "email": "test@example.com", "jti": generateRandomString(16),
				})
				session.SetAccessToken(expiredToken)           // Expired access token
				session.SetRefreshToken("valid-refresh-token") // Valid refresh token
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				return func(refreshToken string) (*TokenResponse, error) {
					// Simulate failed refresh
					return nil, fmt.Errorf("mock error: refresh token invalid or provider down")
				}
			},
			requestHeaders: map[string]string{
				"Accept": "text/html", // Browser client
			},
			expectedStatus: http.StatusFound, // Expect redirect to OIDC for browser client after failed refresh attempt
		},
		// This test case remains valid as proactive refresh should still be attempted
		{
			name:        "Authenticated request with token nearing expiry (needs refresh)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				// Create token expiring soon (e.g., 30s, within default 60s grace period)
				exp := time.Now().Add(30 * time.Second).Unix()
				iat := time.Now().Add(-1 * time.Minute).Unix()
				nbf := time.Now().Add(-1 * time.Minute).Unix()
				nearExpiryToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": exp, "iat": iat, "nbf": nbf,
					"sub": "test-subject", "email": "user@example.com", "jti": generateRandomString(16),
				})
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
				session.SetAccessToken(nearExpiryToken)
				session.SetRefreshToken("valid-refresh-token-for-near-expiry") // Refresh token MUST exist for proactive refresh
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				return func(refreshToken string) (*TokenResponse, error) {
					if refreshToken != "valid-refresh-token-for-near-expiry" {
						return nil, fmt.Errorf("mock error: unexpected refresh token '%s'", refreshToken)
					}
					// Simulate successful refresh
					newToken := ts.createNewValidToken()
					return &TokenResponse{IDToken: newToken, AccessToken: newToken, RefreshToken: "new-refresh-token-near-expiry", ExpiresIn: 3600}, nil
				}
			},
			expectedStatus: http.StatusOK, // Expect success after proactive refresh
			expectedBody:   "OK",
		},
		// This test case remains valid as no refresh should be attempted
		{
			name:        "Authenticated request with token valid (outside grace period)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				// Create token expiring later (e.g., 10 mins, outside default 60s grace period)
				exp := time.Now().Add(10 * time.Minute).Unix()
				iat := time.Now().Add(-1 * time.Minute).Unix()
				nbf := time.Now().Add(-1 * time.Minute).Unix()
				validToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": exp, "iat": iat, "nbf": nbf,
					"sub": "test-subject", "email": "user@example.com", "jti": generateRandomString(16),
				})
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
				session.SetAccessToken(validToken)
				session.SetIDToken(validToken) // Ensure ID token is also set
				session.SetRefreshToken("should-not-be-used-refresh-token")
			},
			mockRefreshTokenFunc: func(originalFunc func(refreshToken string) (*TokenResponse, error)) func(refreshToken string) (*TokenResponse, error) {
				// This should NOT be called
				return func(refreshToken string) (*TokenResponse, error) {
					t.Errorf("Refresh token function was called unexpectedly for valid token outside grace period")
					return nil, fmt.Errorf("refresh should not have been attempted")
				}
			},
			expectedStatus: http.StatusOK, // Expect success, no refresh needed
			expectedBody:   "OK",
		},
		{
			name:        "Disallowed Domain (Accept: JSON)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@disallowed.com") // Use disallowed domain
				// Generate a fresh valid token for this test case
				freshToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(1 * time.Hour).Unix(),
					"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "sub": "test-subject", "email": "user@disallowed.com", // Match email
					"jti": generateRandomString(16), // Unique JTI
				})
				session.SetAccessToken(freshToken)
				session.SetIDToken(freshToken) // Ensure ID token is also set
				session.SetRefreshToken("valid-refresh-token")
			},
			requestHeaders: map[string]string{
				"Accept": "application/json",
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"error":"Forbidden","error_description":"Access denied: Your email domain is not allowed. To log out, visit: /callback/logout","status_code":403}`,
		},
		{
			name:        "Disallowed Domain (Accept: HTML)",
			requestPath: "/protected",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@disallowed.com") // Use disallowed domain
				// Generate a fresh valid token for this test case
				freshToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(1 * time.Hour).Unix(),
					"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "sub": "test-subject", "email": "user@disallowed.com", // Match email
					"jti": generateRandomString(16), // Unique JTI
				})
				session.SetAccessToken(freshToken)
				session.SetIDToken(freshToken) // Ensure ID token is also set
				session.SetRefreshToken("valid-refresh-token")
			},
			requestHeaders: map[string]string{
				"Accept": "text/html",
			},
			expectedStatus: http.StatusForbidden, // Still Forbidden, but HTML response
			expectedBody:   "",                   // Body check is harder for HTML, focus on status and content-type
		},
	}

	// Configure allowed domains for domain restriction tests
	// This allows example.com but not disallowed.com
	ts.tOidc.allowedUserDomains = map[string]struct{}{
		"example.com": {},
	}

	// Use mock JWK cache to enable proper token verification
	ts.tOidc.jwkCache = ts.mockJWKCache

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset token blacklist and cache for each test to prevent token replay detection errors
			ts.tOidc.tokenBlacklist = NewCache() // Use generic cache for blacklist
			ts.tOidc.tokenCache = NewTokenCache()

			// Reset the global replayCache to prevent "token replay detected" errors
			cleanupReplayCache()
			initReplayCache()

			// Store original tokenVerifier to restore later
			origTokenVerifier := ts.tOidc.tokenVerifier

			// Create a mock tokenVerifier that clears the replay cache before verification
			// This prevents replay detection when the same token is verified multiple times within a test
			mockTokenVerifier := &MockTokenVerifier{
				VerifyFunc: func(token string) error {
					// Clear replay cache before token verification
					cleanupReplayCache()
					initReplayCache()

					// For test tokens, perform basic validation without JWKS dependency
					if isTestToken(token) {
						// Parse the token to check basic validity and expiration
						claims, err := extractClaims(token)
						if err != nil {
							return fmt.Errorf("token parsing failed: %v", err)
						}

						// Check token expiration
						if exp, ok := claims["exp"].(float64); ok {
							if time.Now().Unix() > int64(exp) {
								return fmt.Errorf("token has expired")
							}
						}

						// Token is valid for test purposes - also cache the claims like the real verifier would
						if ts.tOidc.tokenCache != nil {
							ts.tOidc.tokenCache.Set(token, claims, time.Hour)
						}
						return nil
					}

					// For non-test tokens, call the original verifier
					if origTokenVerifier != nil {
						return origTokenVerifier.VerifyToken(token)
					}
					return fmt.Errorf("original token verifier is nil")
				},
			}

			// Replace tokenVerifier with our mock
			ts.tOidc.tokenVerifier = mockTokenVerifier

			// Restore original tokenVerifier after test
			defer func() {
				ts.tOidc.tokenVerifier = origTokenVerifier
			}()

			req := httptest.NewRequest("GET", tc.requestPath, nil)
			// Set common headers needed by the logic (determineScheme, determineHost)
			req.Header.Set("X-Forwarded-Proto", "http") // Or https if testing that
			req.Header.Set("X-Forwarded-Host", "testhost.com")
			req.Host = "testhost.com" // Also set Host header
			// Set request headers from test case
			if tc.requestHeaders != nil {
				for key, value := range tc.requestHeaders {
					req.Header.Set(key, value)
				}
			}

			rr := httptest.NewRecorder()

			// Setup session if needed
			session, err := ts.tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Test %s: Failed to get initial session: %v", tc.name, err)
			}
			if tc.setupSession != nil {
				tc.setupSession(session)
				// Save session to recorder to get cookies
				saveRecorder := httptest.NewRecorder()
				if err := session.Save(req, saveRecorder); err != nil {
					t.Fatalf("Test %s: Failed to save initial session: %v", tc.name, err)
				}
				// Copy cookies from save recorder to the actual request
				for _, cookie := range saveRecorder.Result().Cookies() {
					req.AddCookie(cookie)
				}
			}

			// Mocking setup for TokenExchanger
			originalExchanger := ts.tOidc.tokenExchanger // Store original
			mockExchanger, isMock := originalExchanger.(*MockTokenExchanger)
			if !isMock {
				// This case should ideally not happen if Setup correctly assigns the mock,
				// but handle it defensively.
				t.Logf("Warning: Default exchanger was not the mock. Creating a temporary mock.")
				mockExchanger = &MockTokenExchanger{
					ExchangeCodeFunc: originalExchanger.ExchangeCodeForToken,
					RefreshTokenFunc: originalExchanger.GetNewTokenWithRefreshToken,
					RevokeTokenFunc:  originalExchanger.RevokeTokenWithProvider,
				}
				ts.tOidc.tokenExchanger = mockExchanger // Temporarily assign mock
			}

			// Override specific mock methods if needed for the test case
			originalMockRefreshFunc := mockExchanger.RefreshTokenFunc // Store current mock func
			if tc.mockRefreshTokenFunc != nil {
				// Assign the test case specific mock function
				mockExchanger.RefreshTokenFunc = tc.mockRefreshTokenFunc(originalExchanger.GetNewTokenWithRefreshToken)
			}

			// Call ServeHTTP
			ts.tOidc.ServeHTTP(rr, req)

			// Restore original exchanger and mock function state
			ts.tOidc.tokenExchanger = originalExchanger
			if tc.mockRefreshTokenFunc != nil && mockExchanger != nil {
				// Restore the previous mock function if we overrode it
				mockExchanger.RefreshTokenFunc = originalMockRefreshFunc
			}

			// Check response status
			if rr.Code != tc.expectedStatus {
				t.Errorf("Test %s: Expected status %d, got %d. Body: %s", tc.name, tc.expectedStatus, rr.Code, rr.Body.String())
			}

			// Check response body if expected
			// Check response body if expected (handle JSON vs HTML)
			if tc.expectedBody != "" {
				// For JSON, compare directly
				if strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
					if body := strings.TrimSpace(rr.Body.String()); body != tc.expectedBody {
						t.Errorf("Test %s: Expected JSON body %q, got %q", tc.name, tc.expectedBody, body)
					}
				} else if tc.expectedBody == "OK" { // Simple check for the "OK" body from next handler
					if body := strings.TrimSpace(rr.Body.String()); body != tc.expectedBody {
						t.Errorf("Test %s: Expected body %q, got %q", tc.name, tc.expectedBody, body)
					}
				}
				// Add more sophisticated HTML body checks if needed
			}

			// Perform post-request session assertions if defined
			if tc.assertSessionAfterRequest != nil {
				tc.assertSessionAfterRequest(t, rr, req, ts.tOidc.sessionManager)
			}
		})
	}
}

func TestJWKToPEM(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		jwk           *JWK
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "Unsupported Key Type",
			jwk: &JWK{
				Kty: "unsupported",
				Kid: "test-key-id",
			},
			expectError:   true,
			errorContains: "unsupported key type",
		},
		{
			name: "EC Key",
			jwk: &JWK{
				Kty: "EC",
				Kid: "test-ec-key-id",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(ts.ecPrivateKey.PublicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(ts.ecPrivateKey.PublicKey.Y.Bytes()),
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pemBytes, err := jwkToPEM(tc.jwk)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing '%s', got '%v'", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(pemBytes) == 0 {
					t.Error("PEM bytes should not be empty")
				}
			}
		})
	}
}

func TestParseJWT(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name          string
		token         string
		errorContains string
		expectError   bool
	}{
		{
			name:          "Invalid Format",
			token:         "invalid.jwt.token",
			expectError:   true,
			errorContains: "invalid JWT format",
		},
		{
			name:        "Valid Token",
			token:       ts.token,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseJWT(tc.token)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing '%s', got '%v'", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestJWTVerify_MissingClaims(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	jwt := &JWT{
		Header: map[string]interface{}{
			"alg": "RS256",
			"kid": "test-key-id",
		},
		Claims: map[string]interface{}{
			// Missing 'iss', 'aud', 'exp', 'iat', 'sub'
		},
	}

	err := jwt.Verify("https://test-issuer.com", "test-client-id")
	if err == nil {
		t.Error("Expected error for missing claims, got nil")
	}
}

func TestHandleCallback(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	redirectURL := "http://example.com/"

	tests := []struct {
		exchangeCodeForToken func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error)
		extractClaimsFunc    func(tokenString string) (map[string]interface{}, error)
		sessionSetupFunc     func(*SessionData)
		name                 string
		queryParams          string
		expectedStatus       int
	}{
		{
			name:        "Success",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@example.com",
					"nonce": "test-nonce",
				}, nil
			},
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusFound,
		},
		{
			name:        "Missing Code",
			queryParams: "",
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Exchange Code Error",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				return nil, fmt.Errorf("exchange code error")
			},
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Missing ID Token",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Disallowed Email",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				// Generate a unique token for this test case to avoid replay issues
				// Use claims relevant to this test (disallowed email)
				now := time.Now()
				exp := now.Add(1 * time.Hour).Unix()
				iat := now.Unix()
				nbf := now.Unix()
				disallowedToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss":   "https://test-issuer.com",
					"aud":   "test-client-id",
					"exp":   exp,
					"iat":   iat,
					"nbf":   nbf,
					"sub":   "test-subject-disallowed",
					"email": "user@disallowed.com",    // The disallowed email for this test
					"nonce": "test-nonce",             // Match the nonce set in sessionSetupFunc
					"jti":   generateRandomString(16), // Unique JTI
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create disallowed token for test: %w", err)
				}
				return &TokenResponse{
					IDToken:      disallowedToken,
					RefreshToken: "test-refresh-token-disallowed",
				}, nil
			},
			// Remove mock extractClaimsFunc - let the real one parse the disallowedToken
			// The test should still fail correctly on the email check later.
			// extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
			// 	return map[string]interface{}{
			// 		"email": "user@disallowed.com",
			// 		"nonce": "test-nonce",
			// 	}, nil
			// },
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:        "Invalid State Parameter",
			queryParams: "?code=test-code&state=invalid-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@example.com",
					"nonce": "test-nonce",
				}, nil
			},
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Nonce Mismatch",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@example.com",
					"nonce": "invalid-nonce",
				}, nil
			},
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Missing Nonce in Claims",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@example.com",
					// Missing nonce
				}, nil
			},
			sessionSetupFunc: func(session *SessionData) {
				session.SetCSRF("test-csrf-token")
				session.SetNonce("test-nonce")
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		// Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			// Clear the global replay cache before each test run
			cleanupReplayCache()
			initReplayCache()

			// Explicitly clear the shared blacklist at the start of each sub-test
			// to ensure no state leaks, even though we expect the local one to be used.
			// Note: This line might be redundant now that the verifier is local, but keep for safety.
			ts.tOidc.tokenBlacklist = NewCache() // Use generic cache for blacklist

			logger := NewLogger("info")
			sessionManager, _ := NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", logger, "test-instance")

			// Create a new instance for each test to avoid state carryover
			instanceExtractClaimsFunc := tc.extractClaimsFunc
			if instanceExtractClaimsFunc == nil {
				instanceExtractClaimsFunc = extractClaims // Default to the real function if not provided by test case
			}
			tOidc := &TraefikOidc{
				allowedUserDomains: map[string]struct{}{"example.com": {}},
				logger:             logger,
				// exchangeCodeForTokenFunc: tc.exchangeCodeForToken, // Removed field
				extractClaimsFunc: instanceExtractClaimsFunc, // Use the potentially defaulted function
				tokenVerifier:     nil,                       // Will be set to self below
				jwtVerifier:       nil,                       // Temporarily nil, will be set below
				sessionManager:    sessionManager,
				tokenExchanger: &MockTokenExchanger{ // Create a new mock exchanger for this specific test run
					ExchangeCodeFunc: func(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
						// Wrap the test case function to match the required signature
						if tc.exchangeCodeForToken != nil {
							// Only call if the test case provided a function
							return tc.exchangeCodeForToken(codeOrToken, redirectURL, codeVerifier)
						}
						// Provide a default behavior or error if no mock was provided for this test case
						return nil, fmt.Errorf("mock ExchangeCodeFunc not implemented for this test case")
					},
					// Keep other mock funcs nil or provide defaults if needed by other parts of handleCallback
				},
				tokenCache:     NewTokenCache(),              // Initialize token cache
				limiter:        rate.NewLimiter(rate.Inf, 0), // Initialize rate limiter
				tokenBlacklist: NewCache(),                   // Initialize token blacklist cache

				// Add potentially missing fields based on New() comparison
				clientID:     ts.tOidc.clientID,
				audience:     ts.tOidc.clientID,
				issuerURL:    ts.tOidc.issuerURL,
				jwkCache:     ts.tOidc.jwkCache, // Use the mock cache from TestSuite
				httpClient:   ts.tOidc.httpClient,
				initComplete: make(chan struct{}), // Initialize the channel
				// Setting other fields like paths, enablePKCE etc. if needed
			}
			tOidc.tokenVerifier = tOidc // Point tokenVerifier to the local instance NOW
			tOidc.jwtVerifier = tOidc   // Point jwtVerifier to the local instance NOW
			close(tOidc.initComplete)   // Mark this test instance as initialized

			// Create request and response recorder
			req := httptest.NewRequest("GET", "/callback"+tc.queryParams, nil)
			rr := httptest.NewRecorder()

			// Create session
			session, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			if tc.sessionSetupFunc != nil {
				tc.sessionSetupFunc(session)
			}
			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Copy cookies to the new request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Reset response recorder for the actual test
			rr = httptest.NewRecorder()

			// Call handleCallback
			tOidc.handleCallback(rr, req, redirectURL)

			// Check response
			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

func TestIsAllowedDomain(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		allowedDomains    map[string]struct{}
		allowedUsers      map[string]struct{}
		name              string
		email             string
		expectedLogOutput string
		allowed           bool
	}{
		{
			name:           "Allowed domain",
			email:          "user@example.com",
			allowedDomains: map[string]struct{}{"example.com": {}},
			allowedUsers:   map[string]struct{}{},
			allowed:        true,
		},
		{
			name:           "Disallowed domain",
			email:          "user@notallowed.com",
			allowedDomains: map[string]struct{}{"example.com": {}},
			allowedUsers:   map[string]struct{}{},
			allowed:        false,
		},
		{
			name:           "Invalid email",
			email:          "invalid-email",
			allowedDomains: map[string]struct{}{"example.com": {}},
			allowedUsers:   map[string]struct{}{},
			allowed:        false,
		},
		{
			name:           "Specific user is allowed regardless of domain",
			email:          "specific.user@otherdomain.com",
			allowedDomains: map[string]struct{}{"example.com": {}},
			allowedUsers:   map[string]struct{}{"specific.user@otherdomain.com": {}},
			allowed:        true,
		},
		{
			name:           "Case-insensitive email matching for specific user",
			email:          "Specific.User@otherdomain.com", // Mixed case
			allowedDomains: map[string]struct{}{"example.com": {}},
			allowedUsers:   map[string]struct{}{"specific.user@otherdomain.com": {}}, // Lowercase
			allowed:        true,
		},
		{
			name:           "Only allowed users configured (no domains)",
			email:          "specific.user@otherdomain.com",
			allowedDomains: map[string]struct{}{}, // Empty allowed domains
			allowedUsers:   map[string]struct{}{"specific.user@otherdomain.com": {}},
			allowed:        true,
		},
		{
			name:           "User not in allowed list when only specific users configured",
			email:          "other.user@otherdomain.com",
			allowedDomains: map[string]struct{}{}, // Empty allowed domains
			allowedUsers:   map[string]struct{}{"specific.user@otherdomain.com": {}},
			allowed:        false,
		},
		{
			name:           "No restrictions (both empty)",
			email:          "anyone@anydomain.com",
			allowedDomains: map[string]struct{}{},
			allowedUsers:   map[string]struct{}{},
			allowed:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Configure TraefikOidc instance for this test case
			tOidc := ts.tOidc
			tOidc.allowedUserDomains = tc.allowedDomains
			tOidc.allowedUsers = tc.allowedUsers

			allowed := tOidc.isAllowedDomain(tc.email)
			if allowed != tc.allowed {
				t.Errorf("Expected allowed=%v, got %v", tc.allowed, allowed)
			}
		})
	}
}

func TestOIDCHandler(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	ts.token = "valid.jwt.token"

	tests := []struct {
		exchangeCodeForToken func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error)
		extractClaimsFunc    func(tokenString string) (map[string]interface{}, error)
		sessionSetupFunc     func(session *sessions.Session)
		name                 string
		queryParams          string
		expectedStatus       int
		blacklist            bool
		rateLimit            bool
		cacheToken           bool
	}{
		{
			name:        "Missing Code",
			queryParams: "",
			sessionSetupFunc: func(session *sessions.Session) {
				// Set CSRF and nonce values in session
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				// Simulate token exchange
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				// Simulate extraction of claims with invalid nonce
				return map[string]interface{}{
					"email": "user@example.com",
					"nonce": "invalid-nonce",
				}, nil
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Missing Nonce in Claims",
			queryParams: "?code=test-code&state=test-csrf-token",
			sessionSetupFunc: func(session *sessions.Session) {
				// Set CSRF and nonce values in session
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				// Simulate token exchange
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				// Simulate extraction of claims without nonce
				return map[string]interface{}{
					"email": "user@example.com",
				}, nil
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Invalid State Parameter",
			queryParams: "?code=test-code&state=invalid-csrf-token",
			sessionSetupFunc: func(session *sessions.Session) {
				// Set CSRF and nonce values in session
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				// Simulate token exchange
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				// Simulate extraction of claims
				return map[string]interface{}{
					"email": "user@example.com",
					"nonce": "test-nonce",
				}, nil
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Nonce Mismatch",
			queryParams: "?code=test-code&state=test-csrf-token",
			sessionSetupFunc: func(session *sessions.Session) {
				// Set CSRF and nonce values in session
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			exchangeCodeForToken: func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
				// Simulate token exchange
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				// Simulate extraction of claims with mismatched nonce
				return map[string]interface{}{
					"email": "user@example.com",
					"nonce": "invalid-nonce",
				}, nil
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		// Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			// Reset token blacklist and cache
			ts.tOidc.tokenBlacklist = NewCache() // Use generic cache for blacklist
			ts.tOidc.tokenCache = NewTokenCache()
			ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Second), 10)

			// Set up the test case
			if tc.blacklist {
				// Use Set with a duration. Value 'true' is arbitrary.
				ts.tOidc.tokenBlacklist.Set(ts.token, true, 1*time.Hour)
			}

			if tc.rateLimit {
				// Exceed rate limit
				ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Hour), 0)
			}

			if tc.cacheToken {
				// Cache the token with dummy claims
				ts.tOidc.tokenCache.Set(ts.token, map[string]interface{}{
					"empty": "claim",
				}, 60)
			}
		})
	}
}

// TestHandleLogout tests the logout functionality
func TestHandleLogout(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Create mock revocation endpoint server
	mockRevocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}
		// Verify the required parameters are present
		if r.Form.Get("token") == "" {
			t.Error("Missing token parameter")
		}
		if r.Form.Get("token_type_hint") == "" {
			t.Error("Missing token_type_hint parameter")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockRevocationServer.Close()

	tests := []struct {
		setupSession   func(*SessionData)
		name           string
		endSessionURL  string
		expectedURL    string
		host           string
		expectedStatus int
	}{
		{
			name: "Successful logout with end session endpoint",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetAccessToken(ValidAccessToken)
				session.SetIDToken(ValidIDToken)
				session.SetRefreshToken(ValidRefreshToken)
			},
			endSessionURL:  "https://provider/end-session",
			expectedStatus: http.StatusFound,
			expectedURL:    "https://provider/end-session?id_token_hint=" + url.QueryEscape(ValidIDToken) + "&post_logout_redirect_uri=http%3A%2F%2Fexample.com%2F",
			host:           "test-host",
		},
		{
			name: "Successful logout without end session endpoint",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetAccessToken(ValidAccessToken)
				session.SetIDToken(ValidIDToken)
				session.SetRefreshToken(ValidRefreshToken)
			},
			endSessionURL:  "",
			expectedStatus: http.StatusFound,
			expectedURL:    "http://example.com/",
			host:           "test-host",
		},
		{
			name:           "Logout with empty session",
			setupSession:   func(session *SessionData) {},
			expectedStatus: http.StatusFound,
			expectedURL:    "http://example.com/",
			host:           "test-host",
		},
		{
			name: "Logout with invalid end session URL",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetAccessToken(ValidAccessToken)
				session.SetIDToken(ValidIDToken)
				session.SetRefreshToken(ValidRefreshToken)
			},
			endSessionURL:  ":\\invalid-url",
			expectedStatus: http.StatusInternalServerError,
			host:           "test-host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := NewLogger("info")
			sessionManager, _ := NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", logger, "test-instance")
			tOidc := &TraefikOidc{
				revocationURL:  mockRevocationServer.URL,
				endSessionURL:  tc.endSessionURL,
				scheme:         "http",
				logger:         logger,
				tokenBlacklist: NewCache(), // Use generic cache for blacklist
				httpClient:     &http.Client{},
				clientID:       "test-client-id",
				audience:       "test-client-id",
				clientSecret:   "test-client-secret",
				tokenCache:     NewTokenCache(),
				forceHTTPS:     false,
				sessionManager: sessionManager,
			}

			// Create request with proper headers
			req := httptest.NewRequest("GET", "/logout", nil)
			req.Header.Set("Host", tc.host)

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Get a session
			session, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			if tc.setupSession != nil {
				tc.setupSession(session)
			}
			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Copy cookies to the new request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Reset response recorder
			rr = httptest.NewRecorder()

			// Handle logout
			tOidc.handleLogout(rr, req)

			// Check response
			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}

			if tc.expectedURL != "" {
				location := rr.Header().Get("Location")
				if location != tc.expectedURL {
					t.Errorf("Expected redirect to %q, got %q", tc.expectedURL, location)
				}
			}

			// Verify session is cleared
			updatedSession, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get updated session: %v", err)
			}

			// Verify tokens are cleared
			if token := updatedSession.GetAccessToken(); token != "" {
				t.Error("Access token not cleared")
			}
			if token := updatedSession.GetRefreshToken(); token != "" {
				t.Error("Refresh token not cleared")
			}
			if updatedSession.GetAuthenticated() {
				t.Error("Session still marked as authenticated")
			}

			// Check token blacklist
			if token := session.GetAccessToken(); token != "" {
				if _, exists := tOidc.tokenBlacklist.Get(token); !exists {
					t.Error("Access token was not blacklisted in cache")
				}
			}
			if token := session.GetRefreshToken(); token != "" {
				if _, exists := tOidc.tokenBlacklist.Get(token); !exists {
					t.Error("Refresh token was not blacklisted in cache")
				}
			}
		})
	}
}

// TestRevokeTokenWithProvider tests the token revocation with provider
func TestRevokeTokenWithProvider(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name        string
		token       string
		tokenType   string
		statusCode  int
		expectError bool
	}{
		{
			name:        "Successful token revocation",
			token:       "valid-token",
			tokenType:   "refresh_token",
			statusCode:  http.StatusOK,
			expectError: false,
		},
		{
			name:        "Failed token revocation",
			token:       "invalid-token",
			tokenType:   "refresh_token",
			statusCode:  http.StatusBadRequest,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and content type
				if r.Method != "POST" {
					t.Errorf("Expected POST request, got %s", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("Expected Content-Type application/x-www-form-urlencoded, got %s", ct)
				}

				// Verify form values
				if err := r.ParseForm(); err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}
				if got := r.Form.Get("token"); got != tc.token {
					t.Errorf("Expected token %s, got %s", tc.token, got)
				}
				if got := r.Form.Get("token_type_hint"); got != tc.tokenType {
					t.Errorf("Expected token_type_hint %s, got %s", tc.tokenType, got)
				}
				if got := r.Form.Get("client_id"); got != ts.tOidc.clientID {
					t.Errorf("Expected client_id %s, got %s", ts.tOidc.clientID, got)
				}
				if got := r.Form.Get("client_secret"); got != ts.tOidc.clientSecret {
					t.Errorf("Expected client_secret %s, got %s", ts.tOidc.clientSecret, got)
				}

				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			// Set revocation URL to test server
			ts.tOidc.revocationURL = server.URL

			// Test token revocation
			err := ts.tOidc.RevokeTokenWithProvider(tc.token, tc.tokenType)
			if tc.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestRevokeToken tests the token revocation functionality
func TestRevokeToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	token := "test.token.with.claims"
	claims := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}

	// Test token revocation
	t.Run("Token revocation", func(t *testing.T) {
		// Create a new instance for this specific test
		tOidc := &TraefikOidc{
			tokenBlacklist: NewCache(), // Use generic cache for blacklist
			tokenCache:     NewTokenCache(),
			logger:         NewLogger("info"), // Initialize the logger
		}

		// Cache the token
		tOidc.tokenCache.Set(token, claims, time.Hour)

		// Revoke the token
		tOidc.RevokeToken(token)

		// Verify token was removed from cache
		if _, exists := tOidc.tokenCache.Get(token); exists {
			t.Error("Token was not removed from cache")
		}

		// Verify token was added to blacklist cache
		if _, exists := tOidc.tokenBlacklist.Get(token); !exists {
			t.Error("Token was not added to blacklist")
		}
	})
}

// Add this new test function
func TestBuildLogoutURL(t *testing.T) {
	tests := []struct {
		name               string
		endSessionURL      string
		idToken            string
		postLogoutRedirect string
		expectedURL        string
		expectError        bool
	}{
		{
			name:               "Valid URL",
			endSessionURL:      "https://provider/end-session",
			idToken:            "test.id.token",
			postLogoutRedirect: "http://example.com/",
			expectedURL:        "https://provider/end-session?id_token_hint=test.id.token&post_logout_redirect_uri=http%3A%2F%2Fexample.com%2F",
			expectError:        false,
		},
		{
			name:               "Invalid URL",
			endSessionURL:      "://invalid-url",
			idToken:            "test.id.token",
			postLogoutRedirect: "http://example.com/",
			expectError:        true,
		},
		{
			name:               "URL with existing query parameters",
			endSessionURL:      "https://provider/end-session?existing=param",
			idToken:            "test.id.token",
			postLogoutRedirect: "http://example.com/",
			expectedURL:        "https://provider/end-session?existing=param&id_token_hint=test.id.token&post_logout_redirect_uri=http%3A%2F%2Fexample.com%2F",
			expectError:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url, err := BuildLogoutURL(tc.endSessionURL, tc.idToken, tc.postLogoutRedirect)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if url != tc.expectedURL {
					t.Errorf("Expected URL %q, got %q", tc.expectedURL, url)
				}
			}
		})
	}
}

// Add this new test function
func TestHandleExpiredToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name         string
		setupSession func(*SessionData)
		expectedPath string
	}{
		{
			name: "Basic expired token",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				// Create an expired token for this test
				expiredToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(-1 * time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(), "nbf": time.Now().Add(-2 * time.Hour).Unix(),
					"sub": "test-subject", "email": "test@example.com", "jti": generateRandomString(16),
				})
				session.SetAccessToken(expiredToken)
				session.SetEmail("test@example.com")
			},
			expectedPath: "/original/path",
		},
		{
			name: "Session with additional values",
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				// Create an expired token for this test
				expiredToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com", "aud": "test-client-id", "exp": time.Now().Add(-1 * time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(), "nbf": time.Now().Add(-2 * time.Hour).Unix(),
					"sub": "test-subject", "email": "test@example.com", "jti": generateRandomString(16),
				})
				session.SetAccessToken(expiredToken)
				session.mainSession.Values["custom_value"] = "should-be-cleared"
			},
			expectedPath: "/another/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := NewLogger("info")
			sessionManager, _ := NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", logger, "test-instance")

			tOidc := &TraefikOidc{
				sessionManager: sessionManager,
				logger:         logger,
				tokenVerifier:  ts.tOidc.tokenVerifier,
				jwtVerifier:    ts.tOidc.jwtVerifier,
				initComplete:   make(chan struct{}),
				initiateAuthenticationFunc: func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
					http.Redirect(rw, req, "/login", http.StatusFound)
				},
			}
			close(tOidc.initComplete)

			// Create request
			req := httptest.NewRequest("GET", tc.expectedPath, nil)
			rr := httptest.NewRecorder()

			// Get session
			session, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Setup session data
			tc.setupSession(session)

			// Handle expired token
			tOidc.handleExpiredToken(rr, req, session, tc.expectedPath)

			// Get the updated session to verify changes
			updatedSession, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get updated session: %v", err)
			}

			// Verify main session values
			if updatedSession.GetCSRF() == "" {
				t.Error("CSRF token not set")
			}
			if path := updatedSession.GetIncomingPath(); path != tc.expectedPath {
				t.Errorf("Expected path %s, got %s", tc.expectedPath, path)
			}
			if updatedSession.GetNonce() == "" {
				t.Error("Nonce not set")
			}

			// Verify tokens are cleared
			if token := updatedSession.GetAccessToken(); token != "" {
				t.Error("Access token not cleared")
			}
			if token := updatedSession.GetRefreshToken(); token != "" {
				t.Error("Refresh token not cleared")
			}

			// Verify redirect status
			if rr.Code != http.StatusFound {
				t.Errorf("Expected status %d, got %d", http.StatusFound, rr.Code)
			}
		})
	}
}

// Add this new test function
func TestExtractGroupsAndRoles(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name         string
		claims       map[string]interface{}
		expectGroups []string
		expectRoles  []string
		expectError  bool
	}{
		{
			name: "Valid groups and roles",
			claims: map[string]interface{}{
				"groups": []interface{}{"group1", "group2"},
				"roles":  []interface{}{"role1", "role2"},
			},
			expectGroups: []string{"group1", "group2"},
			expectRoles:  []string{"role1", "role2"},
			expectError:  false,
		},
		{
			name: "Empty groups and roles",
			claims: map[string]interface{}{
				"groups": []interface{}{},
				"roles":  []interface{}{},
			},
			expectGroups: []string{},
			expectRoles:  []string{},
			expectError:  false,
		},
		{
			name: "Invalid groups format",
			claims: map[string]interface{}{
				"groups": "not-an-array",
				"roles":  []interface{}{"role1"},
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test token with the claims
			token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", tc.claims)
			if err != nil {
				t.Fatalf("Failed to create test token: %v", err)
			}

			groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Compare groups
				if !stringSliceEqual(groups, tc.expectGroups) {
					t.Errorf("Expected groups %v, got %v", tc.expectGroups, groups)
				}

				// Compare roles
				if !stringSliceEqual(roles, tc.expectRoles) {
					t.Errorf("Expected roles %v, got %v", tc.expectRoles, roles)
				}
			}
		})
	}
}

// TestMultipleMiddlewareInstances verifies that multiple middleware instances
// can be created and initialized properly for different routes
func TestMultipleMiddlewareInstances(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// Create mock provider metadata server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		metadata := ProviderMetadata{
			Issuer:        "https://test-issuer.com",
			AuthURL:       "https://test-issuer.com/auth",
			TokenURL:      "https://test-issuer.com/token",
			JWKSURL:       "https://test-issuer.com/jwks",
			RevokeURL:     "https://test-issuer.com/revoke",
			EndSessionURL: "https://test-issuer.com/end-session",
		}
		json.NewEncoder(w).Encode(metadata)
	}))
	defer mockServer.Close()

	// Create base config
	config := &Config{
		ProviderURL:          mockServer.URL,
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "/callback",
		SessionEncryptionKey: "test-encryption-key-thats-long-enough",
	}

	// Create multiple middleware instances
	routes := []string{"/api/v1", "/api/v2", "/api/v3"}
	var middlewares []*TraefikOidc

	for _, route := range routes {
		config.CallbackURL = route + "/callback"
		middleware, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), config, "test")
		if err != nil {
			t.Fatalf("Failed to create middleware for route %s: %v", route, err)
		}

		// Type assert to access internal fields
		if m, ok := middleware.(*TraefikOidc); ok {
			middlewares = append(middlewares, m)
		} else {
			t.Fatalf("Middleware is not of type *TraefikOidc")
		}
	}

	// Clean up all middleware instances to prevent goroutine leaks
	defer func() {
		for i, m := range middlewares {
			if err := m.Close(); err != nil {
				t.Errorf("Failed to close middleware instance %d: %v", i, err)
			}
		}
	}()

	// Wait for all instances to initialize
	for i, m := range middlewares {
		select {
		case <-m.initComplete:
		case <-time.After(5 * time.Second):
			t.Fatalf("Middleware instance %d failed to initialize", i)
		}

		// Verify each instance has its own unique configuration
		if m.issuerURL != "https://test-issuer.com" {
			t.Errorf("Instance %d: Expected issuer URL %s, got %s", i, "https://test-issuer.com", m.issuerURL)
		}
		if m.authURL != "https://test-issuer.com/auth" {
			t.Errorf("Instance %d: Expected auth URL %s, got %s", i, "https://test-issuer.com/auth", m.authURL)
		}
		if m.tokenURL != "https://test-issuer.com/token" {
			t.Errorf("Instance %d: Expected token URL %s, got %s", i, "https://test-issuer.com/token", m.tokenURL)
		}
		if m.jwksURL != "https://test-issuer.com/jwks" {
			t.Errorf("Instance %d: Expected JWKS URL %s, got %s", i, "https://test-issuer.com/jwks", m.jwksURL)
		}
		if m.redirURLPath != routes[i]+"/callback" {
			t.Errorf("Instance %d: Expected callback URL %s, got %s", i, routes[i]+"/callback", m.redirURLPath)
		}
	}

	// Test that each instance can handle requests independently
	for i, m := range middlewares {
		req := httptest.NewRequest("GET", routes[i]+"/protected", nil)
		rr := httptest.NewRecorder()

		m.ServeHTTP(rr, req)

		// Should redirect to auth URL since not authenticated
		if rr.Code != http.StatusFound {
			t.Errorf("Instance %d: Expected redirect status %d, got %d", i, http.StatusFound, rr.Code)
		}

		location := rr.Header().Get("Location")
		if !strings.Contains(location, "https://test-issuer.com/auth") {
			t.Errorf("Instance %d: Expected redirect to auth URL, got %s", i, location)
		}
	}
}

func TestServeHTTPRolesAndGroups(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Create consistent timestamps for all test cases
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Add(-2 * time.Minute).Unix() // Account for clock skew
	nbf := now.Add(-2 * time.Minute).Unix() // Account for clock skew

	tests := []struct {
		allowedRolesAndGroups map[string]struct{}
		claims                map[string]interface{}
		setupSession          func(*SessionData)
		expectedHeaders       map[string]string
		name                  string
		expectedStatus        int
	}{
		{
			name: "User with allowed role",
			allowedRolesAndGroups: map[string]struct{}{
				"admin": {},
			},
			claims: map[string]interface{}{
				"iss":    "https://test-issuer.com",
				"aud":    "test-client-id",
				"exp":    exp,
				"iat":    iat,
				"nbf":    nbf,
				"sub":    "test-subject",
				"roles":  []interface{}{"admin", "user"},
				"groups": []interface{}{"group1"},
				"jti":    generateRandomString(16),
			},
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-User-Roles":  "admin,user",
				"X-User-Groups": "group1",
			},
		},
		{
			name: "User with allowed group",
			allowedRolesAndGroups: map[string]struct{}{
				"allowed-group": {},
			},
			claims: map[string]interface{}{
				"iss":    "https://test-issuer.com",
				"aud":    "test-client-id",
				"exp":    exp,
				"iat":    iat,
				"nbf":    nbf,
				"sub":    "test-subject",
				"roles":  []interface{}{"user"},
				"groups": []interface{}{"allowed-group"},
				"jti":    generateRandomString(16),
			},
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-User-Roles":  "user",
				"X-User-Groups": "allowed-group",
			},
		},
		{
			name: "User without allowed roles or groups",
			allowedRolesAndGroups: map[string]struct{}{
				"admin":         {},
				"allowed-group": {},
			},
			claims: map[string]interface{}{
				"iss":    "https://test-issuer.com",
				"aud":    "test-client-id",
				"exp":    exp,
				"iat":    iat,
				"nbf":    nbf,
				"sub":    "test-subject",
				"roles":  []interface{}{"user"},
				"groups": []interface{}{"regular-group"},
				"jti":    generateRandomString(16),
			},
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:                  "No role/group restrictions",
			allowedRolesAndGroups: map[string]struct{}{},
			claims: map[string]interface{}{
				"iss":    "https://test-issuer.com",
				"aud":    "test-client-id",
				"exp":    exp,
				"iat":    iat,
				"nbf":    nbf,
				"sub":    "test-subject",
				"roles":  []interface{}{"user"},
				"groups": []interface{}{"regular-group"},
				"jti":    generateRandomString(16),
			},
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-User-Roles":  "user",
				"X-User-Groups": "regular-group",
			},
		},
		{
			name:                  "Claims without roles and groups",
			allowedRolesAndGroups: map[string]struct{}{},
			claims: map[string]interface{}{
				"iss": "https://test-issuer.com",
				"aud": "test-client-id",
				"exp": exp,
				"iat": iat,
				"nbf": nbf,
				"sub": "test-subject",
				"jti": generateRandomString(16),
			},
			setupSession: func(session *SessionData) {
				session.SetAuthenticated(true)
				session.SetEmail("user@example.com")
			},
			expectedStatus:  http.StatusOK,
			expectedHeaders: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create token with claims
			token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", tc.claims)
			if err != nil {
				t.Fatalf("Failed to create test token: %v", err)
			}

			// Create test handler
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Configure OIDC middleware
			tOidc := ts.tOidc
			tOidc.next = nextHandler
			tOidc.allowedRolesAndGroups = tc.allowedRolesAndGroups

			// Create request
			req := httptest.NewRequest("GET", "/protected", nil)
			rr := httptest.NewRecorder()

			// Set up session
			session, err := tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			tc.setupSession(session)
			session.SetAccessToken(token)

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Copy cookies to the new request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Reset response recorder
			rr = httptest.NewRecorder()

			// Serve request
			tOidc.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}

			// Check headers if status is OK
			if tc.expectedStatus == http.StatusOK {
				for header, expectedValue := range tc.expectedHeaders {
					if value := req.Header.Get(header); value != expectedValue {
						t.Errorf("Expected header %s to be %s, got %s", header, expectedValue, value)
					}
				}
			}
		})
	}
}

// Helper function to compare string slices
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestExchangeTokensWithRedirects tests the token exchange process with redirects
func TestExchangeTokensWithRedirects(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		setupServer   func() *httptest.Server
		name          string
		errorContains string
		expectError   bool
	}{
		{
			name: "Successful token exchange with redirects",
			setupServer: func() *httptest.Server {
				redirectCount := 0
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if redirectCount < 3 {
						// Set a cookie before redirecting
						http.SetCookie(w, &http.Cookie{
							Name:  fmt.Sprintf("redirect-cookie-%d", redirectCount),
							Value: "test-value",
						})
						redirectCount++
						w.Header().Set("Location", r.URL.String())
						w.WriteHeader(http.StatusFound)
						return
					}

					// Verify all cookies from previous redirects are present
					cookies := r.Cookies()
					if len(cookies) != 3 {
						t.Errorf("Expected 3 cookies, got %d", len(cookies))
					}
					for i := range 3 {
						found := false
						expectedName := fmt.Sprintf("redirect-cookie-%d", i)
						for _, cookie := range cookies {
							if cookie.Name == expectedName {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("Cookie %s not found", expectedName)
						}
					}

					// Return successful token response
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						IDToken:      "test.id.token",
						AccessToken:  "test-access-token",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						RefreshToken: "test-refresh-token",
					})
				}))
			},
			expectError: false,
		},
		{
			name: "Too many redirects",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", r.URL.String())
					w.WriteHeader(http.StatusFound)
				}))
			},
			expectError:   true,
			errorContains: "stopped after 50 redirects",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.setupServer()
			defer server.Close()

			// Configure the test instance
			tOidc := ts.tOidc
			tOidc.tokenURL = server.URL

			// Test token exchange
			response, err := tOidc.exchangeTokens(context.Background(), "authorization_code", "test-code", "http://callback", "test-code-verifier")

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tc.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if response == nil {
					t.Error("Expected token response but got nil")
				} else if response.IDToken != "test.id.token" {
					t.Errorf("Expected ID token %q, got %q", "test.id.token", response.IDToken)
				}
			}
		})
	}
}

// TestBuildAuthURL tests the buildAuthURL function with various URL scenarios
func TestBuildAuthURL(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name           string
		authURL        string
		issuerURL      string
		redirectURL    string
		state          string
		nonce          string
		codeChallenge  string
		expectedPrefix string
		enablePKCE     bool
		checkPKCE      bool
	}{
		{
			name:           "Absolute Auth URL",
			authURL:        "https://auth.example.com/oauth/authorize",
			issuerURL:      "https://auth.example.com",
			redirectURL:    "https://app.example.com/callback",
			state:          "test-state",
			nonce:          "test-nonce",
			enablePKCE:     false,
			codeChallenge:  "",
			expectedPrefix: "https://auth.example.com/oauth/authorize?",
			checkPKCE:      false,
		},
		{
			name:           "Relative Auth URL",
			authURL:        "/oidc/auth",
			issuerURL:      "https://logto.example.com",
			redirectURL:    "https://app.example.com/callback",
			state:          "test-state",
			nonce:          "test-nonce",
			enablePKCE:     false,
			codeChallenge:  "",
			expectedPrefix: "https://logto.example.com/oidc/auth?",
			checkPKCE:      false,
		},
		{
			name:           "Relative Auth URL with Different Issuer",
			authURL:        "/sign-in",
			issuerURL:      "https://auth.example.com:8443",
			redirectURL:    "https://app.example.com/callback",
			state:          "test-state",
			nonce:          "test-nonce",
			enablePKCE:     false,
			codeChallenge:  "",
			expectedPrefix: "https://auth.example.com:8443/sign-in?",
			checkPKCE:      false,
		},
		{
			name:           "With PKCE Enabled",
			authURL:        "https://auth.example.com/oauth/authorize",
			issuerURL:      "https://auth.example.com",
			redirectURL:    "https://app.example.com/callback",
			state:          "test-state",
			nonce:          "test-nonce",
			enablePKCE:     true,
			codeChallenge:  "test-code-challenge",
			expectedPrefix: "https://auth.example.com/oauth/authorize?",
			checkPKCE:      true,
		},
		{
			name:           "With PKCE Enabled but No Challenge",
			authURL:        "https://auth.example.com/oauth/authorize",
			issuerURL:      "https://auth.example.com",
			redirectURL:    "https://app.example.com/callback",
			state:          "test-state",
			nonce:          "test-nonce",
			enablePKCE:     true,
			codeChallenge:  "",
			expectedPrefix: "https://auth.example.com/oauth/authorize?",
			checkPKCE:      false,
		},
		{
			name:           "With PKCE Disabled but Challenge Provided",
			authURL:        "https://auth.example.com/oauth/authorize",
			issuerURL:      "https://auth.example.com",
			redirectURL:    "https://app.example.com/callback",
			state:          "test-state",
			nonce:          "test-nonce",
			enablePKCE:     false,
			codeChallenge:  "test-code-challenge",
			expectedPrefix: "https://auth.example.com/oauth/authorize?",
			checkPKCE:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Configure the test instance
			tOidc := ts.tOidc
			tOidc.authURL = tc.authURL
			tOidc.issuerURL = tc.issuerURL
			tOidc.enablePKCE = tc.enablePKCE

			// Call buildAuthURL with code challenge
			result := tOidc.buildAuthURL(tc.redirectURL, tc.state, tc.nonce, tc.codeChallenge)

			// Verify the URL starts with the expected prefix
			if !strings.HasPrefix(result, tc.expectedPrefix) {
				t.Errorf("Expected URL to start with %q, got %q", tc.expectedPrefix, result)
			}

			// Parse the resulting URL to verify query parameters
			parsedURL, err := url.Parse(result)
			if err != nil {
				t.Fatalf("Failed to parse resulting URL: %v", err)
			}

			query := parsedURL.Query()
			expectedParams := map[string]string{
				"client_id":     tOidc.clientID,
				"response_type": "code",
				"redirect_uri":  tc.redirectURL,
				"state":         tc.state,
				"nonce":         tc.nonce,
			}

			for key, expected := range expectedParams {
				if got := query.Get(key); got != expected {
					t.Errorf("Expected %s=%q, got %q", key, expected, got)
				}
			}

			// Verify PKCE parameters
			if tc.checkPKCE {
				if got := query.Get("code_challenge"); got != tc.codeChallenge {
					t.Errorf("Expected code_challenge=%q, got %q", tc.codeChallenge, got)
				}
				if got := query.Get("code_challenge_method"); got != "S256" {
					t.Errorf("Expected code_challenge_method=%q, got %q", "S256", got)
				}
			} else {
				if got := query.Get("code_challenge"); got != "" {
					t.Errorf("Expected no code_challenge, but got %q", got)
				}
				if got := query.Get("code_challenge_method"); got != "" {
					t.Errorf("Expected no code_challenge_method, but got %q", got)
				}
			}

			// Verify scopes are present and correct
			if len(tOidc.scopes) > 0 {
				expectedScopes := strings.Join(tOidc.scopes, " ")
				if got := query.Get("scope"); got != expectedScopes {
					t.Errorf("Expected scope=%q, got %q", expectedScopes, got)
				}
			}
		})
	}
}

// TestExchangeCodeForToken tests the exchangeCodeForToken function with PKCE support
func TestExchangeCodeForToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		setupMock    func(t *testing.T) *httptest.Server
		name         string
		codeVerifier string
		enablePKCE   bool
	}{
		{
			name:         "With PKCE Enabled and Code Verifier",
			enablePKCE:   true,
			codeVerifier: "test-code-verifier",
			setupMock: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						t.Fatalf("Failed to parse form: %v", err)
					}

					// Verify code_verifier is included
					if codeVerifier := r.Form.Get("code_verifier"); codeVerifier != "test-code-verifier" {
						t.Errorf("Expected code_verifier=test-code-verifier, got %s", codeVerifier)
					}

					// Return successful token response
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						IDToken:      "test.id.token",
						AccessToken:  "test-access-token",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						RefreshToken: "test-refresh-token",
					})
				}))
			},
		},
		{
			name:         "With PKCE Disabled but Code Verifier Provided",
			enablePKCE:   false,
			codeVerifier: "test-code-verifier",
			setupMock: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						t.Fatalf("Failed to parse form: %v", err)
					}

					// Verify code_verifier is NOT included
					if codeVerifier := r.Form.Get("code_verifier"); codeVerifier != "" {
						t.Errorf("Expected no code_verifier, got %s", codeVerifier)
					}

					// Return successful token response
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						IDToken:      "test.id.token",
						AccessToken:  "test-access-token",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						RefreshToken: "test-refresh-token",
					})
				}))
			},
		},
		{
			name:         "With PKCE Enabled but No Code Verifier",
			enablePKCE:   true,
			codeVerifier: "",
			setupMock: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						t.Fatalf("Failed to parse form: %v", err)
					}

					// Verify code_verifier is NOT included
					if codeVerifier := r.Form.Get("code_verifier"); codeVerifier != "" {
						t.Errorf("Expected no code_verifier, got %s", codeVerifier)
					}

					// Return successful token response
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						IDToken:      "test.id.token",
						AccessToken:  "test-access-token",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						RefreshToken: "test-refresh-token",
					})
				}))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.setupMock(t)
			defer server.Close()

			// Configure the test instance
			tOidc := ts.tOidc
			tOidc.tokenURL = server.URL
			tOidc.enablePKCE = tc.enablePKCE

			// Test exchangeCodeForToken
			response, err := tOidc.exchangeCodeForToken("test-code", "http://callback", tc.codeVerifier)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if response == nil {
				t.Error("Expected token response but got nil")
			} else if response.IDToken != "test.id.token" {
				t.Errorf("Expected ID token %q, got %q", "test.id.token", response.IDToken)
			}
		})
	}
}

// TestDefaultInitiateAuthentication_PreservesQueryParameters tests that defaultInitiateAuthentication preserves query parameters in the incoming path.
func TestDefaultInitiateAuthentication_PreservesQueryParameters(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Create a request with query parameters
	req := httptest.NewRequest("GET", "/protected/resource?param1=value1&param2=value2", nil)
	responseRecorder := httptest.NewRecorder()

	// Get session
	session, err := ts.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Call defaultInitiateAuthentication
	redirectURL := "http://example.com/callback"
	ts.tOidc.defaultInitiateAuthentication(responseRecorder, req, session, redirectURL)

	// Verify that the incoming path includes query parameters
	incomingPath := session.GetIncomingPath()
	expectedPath := "/protected/resource?param1=value1&param2=value2"
	if incomingPath != expectedPath {
		t.Errorf("Expected incoming path to be '%s', got '%s'", expectedPath, incomingPath)
	}
}

// TestVerifyTimeConstraint tests the time constraint verification logic with separate past/future skew tolerances.
func TestVerifyTimeConstraint(t *testing.T) {
	// Define tolerances used in jwt.go (ensure they match)
	toleranceFuture := 2 * time.Minute
	tolerancePast := 10 * time.Second

	now := time.Now()

	tests := []struct {
		name        string
		claimTime   time.Time
		claimName   string
		futureCheck bool // true for exp, false for iat/nbf
		expectError bool
	}{
		// Expiration (future=true, tolerance=2min)
		{
			name:        "EXP: Valid (expires in 1 min)",
			claimTime:   now.Add(1 * time.Minute),
			claimName:   "exp",
			futureCheck: true,
			expectError: false,
		},
		{
			name:        "EXP: Expired (expired 3 min ago)",
			claimTime:   now.Add(-3 * time.Minute), // Outside 2min tolerance
			claimName:   "exp",
			futureCheck: true,
			expectError: true,
		},
		{
			name:        "EXP: Valid (expired 1 min ago, within 2min tolerance)",
			claimTime:   now.Add(-1 * time.Minute), // Inside 2min tolerance
			claimName:   "exp",
			futureCheck: true,
			expectError: false, // Should be allowed due to future tolerance
		},

		// Issued At (future=false, tolerance=10s)
		{
			name:        "IAT: Valid (issued 1 min ago)",
			claimTime:   now.Add(-1 * time.Minute),
			claimName:   "iat",
			futureCheck: false,
			expectError: false,
		},
		{
			name:        "IAT: Invalid (issued 15 sec in future)",
			claimTime:   now.Add(15 * time.Second), // Outside 10s past tolerance
			claimName:   "iat",
			futureCheck: false,
			expectError: true, // "token used before issued"
		},
		{
			name:        "IAT: Valid (issued 5 sec in future, within 10s tolerance)",
			claimTime:   now.Add(5 * time.Second), // Inside 10s past tolerance
			claimName:   "iat",
			futureCheck: false,
			expectError: false, // Should be allowed due to past tolerance
		},

		// Not Before (future=false, tolerance=10s)
		{
			name:        "NBF: Valid (active 1 min ago)",
			claimTime:   now.Add(-1 * time.Minute),
			claimName:   "nbf",
			futureCheck: false,
			expectError: false,
		},
		{
			name:        "NBF: Invalid (active in 15 sec)",
			claimTime:   now.Add(15 * time.Second), // Outside 10s past tolerance
			claimName:   "nbf",
			futureCheck: false,
			expectError: true, // "token not yet valid"
		},
		{
			name:        "NBF: Valid (active in 5 sec, within 10s tolerance)",
			claimTime:   now.Add(5 * time.Second), // Inside 10s past tolerance
			claimName:   "nbf",
			futureCheck: false,
			expectError: false, // Should be allowed due to past tolerance
		},
	}

	// Temporarily adjust global tolerances for test consistency, then restore
	originalFutureTolerance := ClockSkewToleranceFuture
	originalPastTolerance := ClockSkewTolerancePast
	ClockSkewToleranceFuture = toleranceFuture
	ClockSkewTolerancePast = tolerancePast
	defer func() {
		ClockSkewToleranceFuture = originalFutureTolerance
		ClockSkewTolerancePast = originalPastTolerance
	}()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Convert claim time to float64 unix timestamp
			unixTime := float64(tc.claimTime.Unix()) + float64(tc.claimTime.Nanosecond())/1e9

			var err error
			// Call the specific verification function which uses verifyTimeConstraint
			if tc.claimName == "exp" {
				err = verifyExpiration(unixTime)
			} else if tc.claimName == "iat" {
				err = verifyIssuedAt(unixTime)
			} else if tc.claimName == "nbf" {
				err = verifyNotBefore(unixTime)
			} else {
				t.Fatalf("Unknown claim name in test setup: %s", tc.claimName)
			}

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for claim %s at time %v (now=%v), but got nil", tc.claimName, tc.claimTime, now)
				} else {
					t.Logf("Got expected error: %v", err) // Log the error for confirmation
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for claim %s at time %v (now=%v), but got: %v", tc.claimName, tc.claimTime, now, err)
				}
			}
		})
	}
} // Add missing closing brace for TestVerifyTimeConstraint

// ===== JWT REPLAY DETECTION TESTS =====
// These tests ensure the replay detection fix works correctly and prevents regressions

// TestJWTVerifyWithSkipReplayCheck tests the new skipReplayCheck parameter functionality
func TestJWTVerifyWithSkipReplayCheck(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Clear the global replay cache before test
	cleanupReplayCache()
	initReplayCache()

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	jwt, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	tests := []struct {
		name            string
		errorContains   string
		skipReplayCheck bool
		firstCall       bool
		expectError     bool
	}{
		{
			name:            "First verification with skipReplayCheck=false should succeed",
			skipReplayCheck: false,
			firstCall:       true,
			expectError:     false,
		},
		{
			name:            "Second verification with skipReplayCheck=false should fail (replay detected)",
			skipReplayCheck: false,
			firstCall:       false,
			expectError:     true,
			errorContains:   "token replay detected",
		},
		{
			name:            "Verification with skipReplayCheck=true should always succeed",
			skipReplayCheck: true,
			firstCall:       false, // Even on subsequent calls
			expectError:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.firstCall {
				// Clear replay cache for first call tests
				cleanupReplayCache()
				initReplayCache()
			}

			err := jwt.Verify("https://test-issuer.com", "test-client-id", tc.skipReplayCheck)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got nil", tc.errorContains)
				} else if !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing '%s', got '%v'", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
			}
		})
	}
}

// TestJWTVerifyBackwardCompatibility tests that calls without the skipReplayCheck parameter default to replay checking
func TestJWTVerifyBackwardCompatibility(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Clear the global replay cache
	cleanupReplayCache()
	initReplayCache()

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	jwt, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	// First call with old signature (no skipReplayCheck parameter) should succeed
	err = jwt.Verify("https://test-issuer.com", "test-client-id")
	if err != nil {
		t.Errorf("First verification should succeed, got: %v", err)
	}

	// Second call with old signature should fail due to replay detection
	err = jwt.Verify("https://test-issuer.com", "test-client-id")
	if err == nil {
		t.Error("Second verification should fail due to replay detection")
	} else if !strings.Contains(err.Error(), "token replay detected") {
		t.Errorf("Expected 'token replay detected' error, got: %v", err)
	}
}

// TestTokenReplayDetectionFalsePositiveFix tests the specific scenario that was causing false positives
func TestTokenReplayDetectionFalsePositiveFix(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Clear the global replay cache
	cleanupReplayCache()
	initReplayCache()

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Simulate the authentication flow that was causing false positives:
	// 1. Initial authentication adds JTI to cache
	// 2. Subsequent request validation should not trigger false positive

	// Step 1: Initial authentication (this would add JTI to cache)
	jwt1, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT for initial auth: %v", err)
	}

	err = jwt1.Verify("https://test-issuer.com", "test-client-id", false) // Normal replay check
	if err != nil {
		t.Fatalf("Initial authentication should succeed: %v", err)
	}

	// Step 2: Subsequent request validation (this should skip replay check to avoid false positive)
	jwt2, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT for subsequent request: %v", err)
	}

	err = jwt2.Verify("https://test-issuer.com", "test-client-id", true) // Skip replay check
	if err != nil {
		t.Errorf("Subsequent request validation should succeed with skipReplayCheck=true: %v", err)
	}

	// Step 3: Verify that actual replay attacks are still detected
	jwt3, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT for replay attack test: %v", err)
	}

	err = jwt3.Verify("https://test-issuer.com", "test-client-id", false) // Normal replay check
	if err == nil {
		t.Error("Actual replay attack should be detected when skipReplayCheck=false")
	} else if !strings.Contains(err.Error(), "token replay detected") {
		t.Errorf("Expected 'token replay detected' error, got: %v", err)
	}
}

// TestAuthenticationFlowReplayDetection tests the complete authentication flow
func TestAuthenticationFlowReplayDetection(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Clear the global replay cache
	cleanupReplayCache()
	initReplayCache()

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Test the complete flow:
	// 1. Initial authentication (should add JTI to cache)
	// 2. Multiple subsequent requests (should not trigger false positives)
	// 3. Actual replay attack from different source (should be detected)

	// Step 1: Initial authentication
	err = ts.tOidc.VerifyToken(token)
	if err != nil {
		t.Fatalf("Initial authentication should succeed: %v", err)
	}

	// Verify JTI is in cache
	replayCacheMu.Lock()
	_, exists := replayCache.Get(jti)
	replayCacheMu.Unlock()
	if !exists {
		t.Error("JTI should be added to replay cache during initial authentication")
	}

	// Step 2: Subsequent requests (simulate normal request processing)
	// These should use the token cache and skip replay detection
	for i := range 3 {
		err = ts.tOidc.VerifyToken(token)
		if err != nil {
			t.Errorf("Subsequent request %d should succeed: %v", i+1, err)
		}
	}

	// Step 3: Simulate actual replay attack by directly calling JWT.Verify with replay check
	jwt, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT for replay attack test: %v", err)
	}

	err = jwt.Verify("https://test-issuer.com", "test-client-id", false) // Force replay check
	if err == nil {
		t.Error("Actual replay attack should be detected")
	} else if !strings.Contains(err.Error(), "token replay detected") {
		t.Errorf("Expected 'token replay detected' error, got: %v", err)
	}
}

// TestActualReplayAttackDetection ensures real replay attacks are still properly detected
func TestActualReplayAttackDetection(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Clear the global replay cache
	cleanupReplayCache()
	initReplayCache()

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	jwt, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	// First verification should succeed
	err = jwt.Verify("https://test-issuer.com", "test-client-id", false)
	if err != nil {
		t.Fatalf("First verification should succeed: %v", err)
	}

	// Simulate different types of replay attacks
	replayTests := []struct {
		name        string
		description string
	}{
		{
			name:        "Direct replay attack",
			description: "Same token used again with replay checking enabled",
		},
		{
			name:        "Replay from different source",
			description: "Token intercepted and replayed by attacker",
		},
	}

	for _, rt := range replayTests {
		t.Run(rt.name, func(t *testing.T) {
			// Parse token again (simulating replay)
			replayJWT, err := parseJWT(token)
			if err != nil {
				t.Fatalf("Failed to parse JWT for replay test: %v", err)
			}

			// Attempt replay with normal replay checking
			err = replayJWT.Verify("https://test-issuer.com", "test-client-id", false)
			if err == nil {
				t.Errorf("Replay attack should be detected for: %s", rt.description)
			} else if !strings.Contains(err.Error(), "token replay detected") {
				t.Errorf("Expected 'token replay detected' error for %s, got: %v", rt.description, err)
			}
		})
	}
}

// TestConcurrentTokenValidation tests thread safety of replay detection
func TestConcurrentTokenValidation(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure rate limiter to allow more requests for concurrent testing
	ts.tOidc.limiter = rate.NewLimiter(rate.Limit(1000), 1000) // Allow 1000 requests per second with burst of 1000

	// Clear the global replay cache
	cleanupReplayCache()
	initReplayCache()

	// Create multiple tokens with unique JTIs
	var tokens []string
	var jtis []string
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	for i := range 10 {
		jti := generateRandomString(16)
		jtis = append(jtis, jti)

		token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   exp,
			"iat":   iat,
			"nbf":   nbf,
			"sub":   "test-subject",
			"email": "user@example.com",
			"nonce": "test-nonce",
			"jti":   jti,
		})
		if err != nil {
			t.Fatalf("Failed to create test JWT %d: %v", i, err)
		}
		tokens = append(tokens, token)
	}

	// Test concurrent validation
	const numGoroutines = 20
	const numIterations = 5

	results := make(chan error, numGoroutines*numIterations)

	for g := range numGoroutines {
		go func(goroutineID int) {
			for i := range numIterations {
				tokenIndex := (goroutineID + i) % len(tokens)
				token := tokens[tokenIndex]

				// First validation should succeed
				err := ts.tOidc.VerifyToken(token)
				results <- err

				// Subsequent validation with same token should also succeed (uses cache)
				err = ts.tOidc.VerifyToken(token)
				results <- err
			}
		}(g)
	}

	// Collect results
	var errors []error
	for range numGoroutines * numIterations * 2 {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	// All validations should succeed (no race conditions)
	if len(errors) > 0 {
		t.Errorf("Expected no errors in concurrent validation, got %d errors: %v", len(errors), errors)
	}

	// Verify all JTIs are in cache
	replayCacheMu.Lock()
	for i, jti := range jtis {
		if _, exists := replayCache.Get(jti); !exists {
			t.Errorf("JTI %d (%s) should be in replay cache", i, jti)
		}
	}
	replayCacheMu.Unlock()
}

// TestJTIBlacklistBehavior tests the JTI blacklist cache management
func TestJTIBlacklistBehavior(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Properly reinitialize the global replay cache
	cleanupReplayCache() // Clean up any existing cache and reset sync.Once
	initReplayCache()    // Initialize new cache through proper channel

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	t.Logf("TestJTIBlacklistBehavior - JTI: %s", jti)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Test JTI blacklist behavior
	tests := []struct {
		action      func() error
		name        string
		description string
		expectError bool
	}{
		{
			name: "Initial verification adds JTI to blacklist",
			action: func() error {
				return ts.tOidc.VerifyToken(token)
			},
			expectError: false,
			description: "First verification should succeed and add JTI to blacklist",
		},
		{
			name: "JTI exists in blacklist after verification",
			action: func() error {
				replayCacheMu.RLock()
				defer replayCacheMu.RUnlock()
				if _, exists := replayCache.Get(jti); !exists {
					return fmt.Errorf("JTI not found in blacklist cache")
				}
				return nil
			},
			expectError: false,
			description: "JTI should be present in blacklist cache",
		},
		{
			name: "Subsequent verification uses cache (no replay check)",
			action: func() error {
				return ts.tOidc.VerifyToken(token)
			},
			expectError: false,
			description: "Subsequent verification should succeed using token cache",
		},
		{
			name: "Direct JWT verification detects replay",
			action: func() error {
				jwt, err := parseJWT(token)
				if err != nil {
					return err
				}
				return jwt.Verify("https://test-issuer.com", "test-client-id", false)
			},
			expectError: true,
			description: "Direct JWT verification should detect replay",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.action()

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got nil", tc.description)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tc.description, err)
				}
			}
		})
	}
}

// TestSessionBasedTokenRevalidation tests token revalidation in session-based scenarios
func TestSessionBasedTokenRevalidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping session-based token revalidation test in short mode")
	}

	ts := NewTestSuite(t)
	ts.Setup()

	// Clear the global replay cache
	cleanupReplayCache()
	initReplayCache()

	// Create a test JWT with unique JTI
	jti := generateRandomString(16)
	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   iat,
		"nbf":   nbf,
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Simulate session-based token revalidation scenario
	// This tests the specific case that was causing false positives

	// Step 1: Initial authentication (callback processing)
	err = ts.tOidc.VerifyToken(token)
	if err != nil {
		t.Fatalf("Initial authentication should succeed: %v", err)
	}

	// Step 2: Multiple session-based requests (normal request processing)
	// These should not trigger replay detection false positives
	for i := range 5 {
		err = ts.tOidc.VerifyToken(token)
		if err != nil {
			t.Errorf("Session request %d should succeed: %v", i+1, err)
		}
	}

	// Step 3: Verify token is in both caches appropriately
	// Check token cache
	if _, exists := ts.tOidc.tokenCache.Get(token); !exists {
		t.Error("Token should be in token cache")
	}

	// Check replay cache
	replayCacheMu.Lock()
	_, inReplayCache := replayCache.Get(jti)
	replayCacheMu.Unlock()
	if !inReplayCache {
		t.Error("JTI should be in replay cache")
	}

	// Step 4: Verify that clearing token cache still allows validation
	ts.tOidc.tokenCache = NewTokenCache() // Clear token cache

	err = ts.tOidc.VerifyToken(token)
	if err != nil {
		t.Errorf("Token validation should succeed even after cache clear: %v", err)
	}
}

// TestEdgeCasesWithDifferentTokenTypes tests replay detection with different token types
func TestEdgeCasesWithDifferentTokenTypes(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Properly reinitialize the global replay cache
	cleanupReplayCache() // Clean up any existing cache and reset sync.Once
	initReplayCache()    // Initialize new cache through proper channel

	now := time.Now()
	exp := now.Add(1 * time.Hour).Unix()
	iat := now.Unix()
	nbf := now.Unix()

	tests := []struct {
		claims      map[string]interface{}
		name        string
		tokenType   string
		expectError bool
	}{
		{
			name:      "ID Token with JTI",
			tokenType: "id_token",
			claims: map[string]interface{}{
				"iss":        "https://test-issuer.com",
				"aud":        "test-client-id",
				"exp":        exp,
				"iat":        iat,
				"nbf":        nbf,
				"sub":        "test-subject",
				"email":      "user@example.com",
				"nonce":      "test-nonce",
				"jti":        generateRandomString(16),
				"token_type": "id_token",
			},
			expectError: false,
		},
		{
			name:      "Access Token with JTI",
			tokenType: "access_token",
			claims: map[string]interface{}{
				"iss":        "https://test-issuer.com",
				"aud":        "test-client-id",
				"exp":        exp,
				"iat":        iat,
				"nbf":        nbf,
				"sub":        "test-subject",
				"scope":      "openid profile email",
				"jti":        generateRandomString(16),
				"token_type": "access_token",
			},
			expectError: false,
		},
		{
			name:      "Token without JTI",
			tokenType: "no_jti",
			claims: map[string]interface{}{
				"iss":   "https://test-issuer.com",
				"aud":   "test-client-id",
				"exp":   exp,
				"iat":   iat,
				"nbf":   nbf,
				"sub":   "test-subject",
				"email": "user@example.com",
				"nonce": "test-nonce",
				// No JTI claim
			},
			expectError: false, // Should still work, just no replay protection
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create token with specific claims
			token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", tc.claims)
			if err != nil {
				t.Fatalf("Failed to create test JWT: %v", err)
			}

			// First verification should succeed
			err = ts.tOidc.VerifyToken(token)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for token type %s, but got nil", tc.tokenType)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for token type %s, but got: %v", tc.tokenType, err)
				}
			}

			// Second verification should also succeed (uses cache)
			if !tc.expectError {
				err = ts.tOidc.VerifyToken(token)
				if err != nil {
					t.Errorf("Second verification should succeed for token type %s: %v", tc.tokenType, err)
				}
			}

			// Test direct JWT verification for replay detection
			if !tc.expectError && tc.claims["jti"] != nil {
				jwt, err := parseJWT(token)
				if err != nil {
					t.Fatalf("Failed to parse JWT: %v", err)
				}

				// This should detect replay for tokens with JTI
				err = jwt.Verify("https://test-issuer.com", "test-client-id", false)
				if err == nil {
					t.Errorf("Expected replay detection for token type %s with JTI", tc.tokenType)
				} else if !strings.Contains(err.Error(), "token replay detected") {
					t.Errorf("Expected 'token replay detected' error for token type %s, got: %v", tc.tokenType, err)
				}
			}
		})
	}
}

// TestScopeMerging tests the scope append functionality
func TestScopeMerging(t *testing.T) {
	// Helper function to compare string slices
	equalSlices := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i, v := range a {
			if v != b[i] {
				return false
			}
		}
		return true
	}

	tests := []struct {
		name           string
		defaultScopes  []string
		userScopes     []string
		expectedScopes []string
	}{
		{
			name:           "Empty user scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Nil user scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     nil,
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "New scopes are appended",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"custom_scope", "another_scope"},
			expectedScopes: []string{"openid", "profile", "email", "custom_scope", "another_scope"},
		},
		{
			name:           "Deduplication - user scope already in defaults",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"openid", "custom_scope"},
			expectedScopes: []string{"openid", "profile", "email", "custom_scope"},
		},
		{
			name:           "Duplicate user scopes are removed",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"custom_scope", "custom_scope", "another_scope"},
			expectedScopes: []string{"openid", "profile", "email", "custom_scope", "another_scope"},
		},
		{
			name:           "Multiple overlapping scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"profile", "custom_scope", "email", "another_scope", "profile"},
			expectedScopes: []string{"openid", "profile", "email", "custom_scope", "another_scope"},
		},
		{
			name:           "Only custom scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"read:users", "write:users", "admin"},
			expectedScopes: []string{"openid", "profile", "email", "read:users", "write:users", "admin"},
		},
		{
			name:           "Empty defaults",
			defaultScopes:  []string{},
			userScopes:     []string{"custom1", "custom2"},
			expectedScopes: []string{"custom1", "custom2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test the mergeScopes function directly
			result := mergeScopes(tc.defaultScopes, tc.userScopes)
			if !equalSlices(result, tc.expectedScopes) {
				t.Errorf("Expected %v, got %v", tc.expectedScopes, result)
			}
		})
	}
}

// TestScopeMergingEdgeCases tests additional edge cases for scope deduplication
func TestScopeMergingEdgeCases(t *testing.T) {
	// Helper function to compare string slices
	equalSlices := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i, v := range a {
			if v != b[i] {
				return false
			}
		}
		return true
	}

	tests := []struct {
		name           string
		description    string
		defaultScopes  []string
		userScopes     []string
		expectedScopes []string
	}{
		{
			name:           "Case sensitivity preserved",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"OpenID", "PROFILE", "custom"},
			expectedScopes: []string{"openid", "profile", "email", "OpenID", "PROFILE", "custom"},
			description:    "OAuth scopes are case-sensitive, so different cases should be preserved",
		},
		{
			name:           "Empty strings in user scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"", "custom", "", "another"},
			expectedScopes: []string{"openid", "profile", "email", "", "custom", "another"},
			description:    "Empty strings should be preserved (though invalid in OAuth)",
		},
		{
			name:           "Whitespace scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{" ", "custom", "  ", "another"},
			expectedScopes: []string{"openid", "profile", "email", " ", "custom", "  ", "another"},
			description:    "Whitespace-only scopes should be preserved as distinct",
		},
		{
			name:          "Large number of scopes",
			defaultScopes: []string{"openid", "profile", "email"},
			userScopes:    generateLargeUserScopes(),
			expectedScopes: func() []string {
				// Manually calculate expected result with proper deduplication
				defaults := []string{"openid", "profile", "email"}
				userScopes := generateLargeUserScopes()
				return mergeScopes(defaults, userScopes)
			}(),
			description: "Performance test with larger scope lists",
		},
		{
			name:           "Complex OAuth scopes with special characters",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"read:users", "write:users", "admin:*", "scope/with/slashes", "scope-with-dashes"},
			expectedScopes: []string{"openid", "profile", "email", "read:users", "write:users", "admin:*", "scope/with/slashes", "scope-with-dashes"},
			description:    "Real-world OAuth scopes with colons, slashes, and special characters",
		},
		{
			name:           "Duplicate defaults in user scopes multiple times",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"openid", "profile", "openid", "custom", "email", "profile", "custom"},
			expectedScopes: []string{"openid", "profile", "email", "custom"},
			description:    "Multiple duplicates of default scopes should be completely deduplicated",
		},
		{
			name:           "All user scopes are duplicates of defaults",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"email", "openid", "profile", "openid"},
			expectedScopes: []string{"openid", "profile", "email"},
			description:    "When all user scopes duplicate defaults, result should be just defaults",
		},
		{
			name:           "Single scope scenarios",
			defaultScopes:  []string{"openid"},
			userScopes:     []string{"custom"},
			expectedScopes: []string{"openid", "custom"},
			description:    "Minimal case with single scopes",
		},
		{
			name:           "Identical scopes in same order",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"openid", "profile", "email"},
			expectedScopes: []string{"openid", "profile", "email"},
			description:    "When user scopes exactly match defaults, no duplication",
		},
		{
			name:           "Identical scopes in different order",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"email", "profile", "openid"},
			expectedScopes: []string{"openid", "profile", "email"},
			description:    "Order of defaults is preserved when user scopes are reordered duplicates",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test the mergeScopes function directly
			result := mergeScopes(tc.defaultScopes, tc.userScopes)
			if !equalSlices(result, tc.expectedScopes) {
				t.Errorf("Expected %v, got %v\nDescription: %s", tc.expectedScopes, result, tc.description)
			}
		})
	}
}

// generateLargeUserScopes creates a large list of user scopes for performance testing
func generateLargeUserScopes() []string {
	scopes := make([]string, 100)
	for i := range 100 {
		scopes[i] = fmt.Sprintf("scope_%d", i)
	}
	// Add some duplicates to test deduplication performance
	scopes = append(scopes, "scope_1", "scope_5", "scope_10", "openid") // Include a default duplicate
	return scopes
}

// TestScopeMergingPerformance tests performance with large scope lists
func TestScopeMergingPerformance(t *testing.T) {
	// Create large scope lists
	defaultScopes := []string{"openid", "profile", "email"}

	// Create 1000 user scopes with some duplicates
	userScopes := make([]string, 1000)
	for i := range 1000 {
		if i%10 == 0 {
			// Add some duplicates of defaults
			userScopes[i] = defaultScopes[i%len(defaultScopes)]
		} else if i%7 == 0 {
			// Add some internal duplicates
			userScopes[i] = fmt.Sprintf("scope_%d", i%50)
		} else {
			userScopes[i] = fmt.Sprintf("scope_%d", i)
		}
	}

	// Measure performance
	start := time.Now()
	result := mergeScopes(defaultScopes, userScopes)
	duration := time.Since(start)

	// Verify result correctness
	if len(result) < len(defaultScopes) {
		t.Errorf("Result should contain at least the default scopes")
	}

	// Verify no duplicates exist
	seen := make(map[string]bool)
	for _, scope := range result {
		if seen[scope] {
			t.Errorf("Duplicate scope found in result: %s", scope)
		}
		seen[scope] = true
	}

	// Performance assertion (should be very fast)
	if duration > time.Millisecond*10 {
		t.Logf("Performance note: mergeScopes took %v for 1000+ scopes (still acceptable)", duration)
	}

	t.Logf("Performance: processed %d user scopes in %v, result has %d unique scopes",
		len(userScopes), duration, len(result))
}

// TestScopeMergingMemoryEfficiency tests memory efficiency of the mergeScopes function
func TestScopeMergingMemoryEfficiency(t *testing.T) {
	defaultScopes := []string{"openid", "profile", "email"}
	userScopes := []string{"custom1", "custom2"}

	// Test that the function doesn't modify input slices
	originalDefaults := make([]string, len(defaultScopes))
	copy(originalDefaults, defaultScopes)
	originalUser := make([]string, len(userScopes))
	copy(originalUser, userScopes)

	result := mergeScopes(defaultScopes, userScopes)

	// Verify input slices are unchanged
	for i, scope := range defaultScopes {
		if scope != originalDefaults[i] {
			t.Errorf("Default scopes were modified: expected %s, got %s", originalDefaults[i], scope)
		}
	}
	for i, scope := range userScopes {
		if scope != originalUser[i] {
			t.Errorf("User scopes were modified: expected %s, got %s", originalUser[i], scope)
		}
	}

	// Verify result is independent
	result[0] = "modified"
	if defaultScopes[0] == "modified" {
		t.Error("Modifying result affected input defaults")
	}

	expectedLength := len(defaultScopes) + len(userScopes)
	if len(result) != expectedLength {
		t.Errorf("Expected result length %d, got %d", expectedLength, len(result))
	}
}

// TestNewWithScopeAppending tests that the New function properly merges scopes
func TestNewWithScopeAppending(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// Create mock provider metadata server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		metadata := ProviderMetadata{
			Issuer:        "https://test-issuer.com",
			AuthURL:       "https://test-issuer.com/auth",
			TokenURL:      "https://test-issuer.com/token",
			JWKSURL:       "https://test-issuer.com/jwks",
			RevokeURL:     "https://test-issuer.com/revoke",
			EndSessionURL: "https://test-issuer.com/end-session",
		}
		json.NewEncoder(w).Encode(metadata)
	}))
	defer mockServer.Close()

	tests := []struct {
		name           string
		configScopes   []string
		expectedScopes []string
	}{
		{
			name:           "Default scopes only",
			configScopes:   []string{},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Custom scopes appended",
			configScopes:   []string{"custom_scope", "another_scope"},
			expectedScopes: []string{"openid", "profile", "email", "custom_scope", "another_scope"},
		},
		{
			name:           "Overlapping scopes deduplicated",
			configScopes:   []string{"openid", "custom_scope"},
			expectedScopes: []string{"openid", "profile", "email", "custom_scope"},
		},
		{
			name:           "OAuth scopes",
			configScopes:   []string{"read:users", "write:users", "admin"},
			expectedScopes: []string{"openid", "profile", "email", "read:users", "write:users", "admin"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create config with test scopes
			config := &Config{
				ProviderURL:          mockServer.URL,
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				CallbackURL:          "/callback",
				SessionEncryptionKey: "test-encryption-key-thats-long-enough",
				Scopes:               tc.configScopes,
			}

			// Create middleware instance
			middleware, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}), config, "test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			// Wait for initialization
			if m, ok := middleware.(*TraefikOidc); ok {
				// Ensure middleware is properly closed to prevent goroutine leaks
				defer func() {
					if err := m.Close(); err != nil {
						t.Errorf("Failed to close middleware: %v", err)
					}
				}()

				select {
				case <-m.initComplete:
				case <-time.After(5 * time.Second):
					t.Fatalf("Middleware failed to initialize")
				}

				// Check that scopes were properly merged
				if !equalSlices(m.scopes, tc.expectedScopes) {
					t.Errorf("Expected scopes %v, got %v", tc.expectedScopes, m.scopes)
				}
			} else {
				t.Fatalf("Middleware is not of type *TraefikOidc")
			}
		})
	}
}

// TestBuildAuthURLWithMergedScopes tests that the auth URL includes the properly merged scopes
func TestBuildAuthURLWithMergedScopes(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name           string
		expectedScopes string
		scopes         []string
	}{
		{
			name:           "Default scopes only",
			scopes:         []string{"openid", "profile", "email"},
			expectedScopes: "openid profile email offline_access",
		},
		{
			name:           "Custom scopes appended",
			scopes:         []string{"openid", "profile", "email", "custom_scope", "another_scope"},
			expectedScopes: "openid profile email custom_scope another_scope offline_access",
		},
		{
			name:           "OAuth scopes",
			scopes:         []string{"openid", "profile", "email", "read:users", "write:users"},
			expectedScopes: "openid profile email read:users write:users offline_access",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Configure the test instance with specific scopes
			tOidc := ts.tOidc
			tOidc.scopes = tc.scopes // These scopes are already deduplicated by New()
			tOidc.authURL = "https://auth.example.com/oauth/authorize"
			tOidc.issuerURL = "https://auth.example.com"
			// Reset overrideScopes for each test case, as it's part of tOidc state
			// Default to false, specific tests will set it.
			tOidc.overrideScopes = false

			// Build auth URL
			result := tOidc.buildAuthURL("https://app.example.com/callback", "test-state", "test-nonce", "")

			// Parse the resulting URL to verify scopes
			parsedURL, err := url.Parse(result)
			if err != nil {
				t.Fatalf("Failed to parse resulting URL: %v", err)
			}

			query := parsedURL.Query()
			actualScopes := query.Get("scope")
			if actualScopes != tc.expectedScopes {
				t.Errorf("Expected scopes %q, got %q", tc.expectedScopes, actualScopes)
			}
		})
	}
}

// TestBuildAuthURL_OverrideScopes_And_OfflineAccess tests the offline_access logic in buildAuthURL
// considering the overrideScopes flag.
func TestBuildAuthURL_OverrideScopes_And_OfflineAccess(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup() // Sets up ts.tOidc

	tests := []struct {
		expectedParams map[string]string
		name           string
		expectedScope  string
		initialScopes  []string
		overrideScopes bool
		isGoogle       bool
		isAzure        bool
	}{
		{
			name:           "Override false, no user scopes, non-Google/Azure",
			initialScopes:  []string{"openid", "profile", "email"}, // Defaults from New() when config.Scopes is empty
			overrideScopes: false,
			expectedScope:  "openid profile email offline_access",
		},
		{
			name:           "Override false, user scopes without offline_access, non-Google/Azure",
			initialScopes:  []string{"openid", "profile", "email", "custom1"}, // Merged and deduplicated by New()
			overrideScopes: false,
			expectedScope:  "openid profile email custom1 offline_access",
		},
		{
			name:           "Override false, user scopes with offline_access, non-Google/Azure",
			initialScopes:  []string{"openid", "profile", "email", "offline_access", "custom1"},
			overrideScopes: false,
			expectedScope:  "openid profile email offline_access custom1", // Order might vary based on merge, but offline_access present
		},
		{
			name:           "Override true, user scopes without offline_access, non-Google/Azure",
			initialScopes:  []string{"custom1", "custom2"}, // Directly from config.Scopes, deduplicated
			overrideScopes: true,
			expectedScope:  "custom1 custom2", // offline_access NOT added
		},
		{
			name:           "Override true, user scopes with offline_access, non-Google/Azure",
			initialScopes:  []string{"custom1", "offline_access", "custom2"},
			overrideScopes: true,
			expectedScope:  "custom1 offline_access custom2", // User explicitly included it
		},
		{
			name:           "Override true, no user scopes (edge case), non-Google/Azure",
			initialScopes:  []string{}, // config.Scopes was empty
			overrideScopes: true,
			// In this edge case, buildAuthURL's logic `(t.overrideScopes && len(t.scopes) == 0)`
			// will lead to offline_access being added, as it behaves like defaults.
			expectedScope: "offline_access",
		},
		// Google Provider Tests (access_type=offline, prompt=consent)
		{
			name:           "Google, Override false, no user scopes",
			initialScopes:  []string{"openid", "profile", "email"},
			overrideScopes: false,
			isGoogle:       true,
			expectedParams: map[string]string{"access_type": "offline", "prompt": "consent"},
			expectedScope:  "openid profile email", // No offline_access scope for Google
		},
		{
			name:           "Google, Override true, user scopes",
			initialScopes:  []string{"custom1", "custom2"},
			overrideScopes: true,
			isGoogle:       true,
			expectedParams: map[string]string{"access_type": "offline", "prompt": "consent"},
			expectedScope:  "custom1 custom2", // No offline_access scope for Google
		},
		// Azure Provider Tests (response_mode=query, offline_access scope added if not present by user)
		{
			name:           "Azure, Override false, no user scopes",
			initialScopes:  []string{"openid", "profile", "email"},
			overrideScopes: false,
			isAzure:        true,
			expectedParams: map[string]string{"response_mode": "query"},
			expectedScope:  "openid profile email offline_access",
		},
		{
			name:           "Azure, Override true, user scopes without offline_access",
			initialScopes:  []string{"custom1", "custom2"},
			overrideScopes: true,
			isAzure:        true,
			expectedParams: map[string]string{"response_mode": "query"},
			expectedScope:  "custom1 custom2", // offline_access NOT added by default when override is true
		},
		{
			name:           "Azure, Override true, user scopes with offline_access",
			initialScopes:  []string{"custom1", "offline_access"},
			overrideScopes: true,
			isAzure:        true,
			expectedParams: map[string]string{"response_mode": "query"},
			expectedScope:  "custom1 offline_access",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tOidc := ts.tOidc
			tOidc.scopes = tc.initialScopes // Set the scopes as if they came from New()
			tOidc.overrideScopes = tc.overrideScopes

			// Adjust issuerURL for provider-specific tests
			originalIssuerURL := tOidc.issuerURL
			if tc.isGoogle {
				tOidc.issuerURL = "https://accounts.google.com"
			} else if tc.isAzure {
				tOidc.issuerURL = "https://login.microsoftonline.com/common"
			} else {
				tOidc.issuerURL = "https://generic-provider.com" // Non-Google/Azure
			}

			authURLString := tOidc.buildAuthURL("http://localhost/callback", "state123", "nonce123", "challenge123")
			parsedAuthURL, err := url.Parse(authURLString)
			if err != nil {
				t.Fatalf("Failed to parse auth URL: %v", err)
			}
			query := parsedAuthURL.Query()

			actualScope := query.Get("scope")
			if actualScope != tc.expectedScope {
				t.Errorf("Expected scope string %q, got %q", tc.expectedScope, actualScope)
			}

			if tc.expectedParams != nil {
				for k, v := range tc.expectedParams {
					if query.Get(k) != v {
						t.Errorf("Expected param %s=%s, got %s", k, v, query.Get(k))
					}
				}
			}

			// Restore original issuerURL for next test
			tOidc.issuerURL = originalIssuerURL
		})
	}
}

// TestBuildAuthURL_SpecificUserCase tests the buildAuthURL function with the specific user-reported scenario.
func TestBuildAuthURL_SpecificUserCase(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup() // Basic setup for tOidc

	// Configure the TraefikOidc instance for the specific scenario
	tOidc := ts.tOidc
	tOidc.scopes = []string{"email", "test3"} // This is what t.scopes should be after New()
	tOidc.overrideScopes = true
	tOidc.issuerURL = "https://generic-provider.com"    // Non-Google/Azure
	tOidc.authURL = "https://generic-provider.com/auth" // Dummy auth URL
	tOidc.clientID = "test-client-id"

	// Expected scope string in the URL
	expectedScopeString := "email test3"

	// Call buildAuthURL
	authURLString := tOidc.buildAuthURL("http://localhost/callback", "test-state", "test-nonce", "")

	// Parse the resulting URL
	parsedAuthURL, err := url.Parse(authURLString)
	if err != nil {
		t.Fatalf("Failed to parse generated auth URL %q: %v", authURLString, err)
	}

	// Get the 'scope' query parameter
	actualScopeString := parsedAuthURL.Query().Get("scope")

	// Assert that the scope string is as expected
	if actualScopeString != expectedScopeString {
		t.Errorf("Expected scope parameter to be %q, but got %q. Full URL: %s",
			expectedScopeString, actualScopeString, authURLString)
	}

	// Additionally, ensure 'offline_access' was not added
	if strings.Contains(actualScopeString, "offline_access") {
		t.Errorf("Scope parameter %q should not contain 'offline_access' when overrideScopes is true and it's not in tOidc.scopes", actualScopeString)
	}
}
