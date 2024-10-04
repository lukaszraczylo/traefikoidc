package traefikoidc

import (
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
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
)

// TestSuite holds common test data and setup
type TestSuite struct {
	t             *testing.T
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	ecPrivateKey  *ecdsa.PrivateKey
	tOidc         *TraefikOidc
	mockJWKCache  *MockJWKCache
	token         string
}

// Setup initializes the test suite
func (ts *TestSuite) Setup() {
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
	ts.token, err = createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"sub":   "test-subject",
		"email": "user@example.com",
	})
	if err != nil {
		ts.t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Common TraefikOidc instance
	ts.tOidc = &TraefikOidc{
		issuerURL:                "https://test-issuer.com",
		clientID:                 "test-client-id",
		clientSecret:             "test-client-secret",
		jwkCache:                 ts.mockJWKCache,
		jwksURL:                  "https://test-jwks-url.com",
		revocationURL:            "https://revocation-endpoint.com",
		limiter:                  rate.NewLimiter(rate.Every(time.Second), 10),
		tokenBlacklist:           NewTokenBlacklist(),
		tokenCache:               NewTokenCache(),
		logger:                   NewLogger("info"),
		store:                    sessions.NewCookieStore([]byte("test-secret-key")),
		allowedUserDomains:       map[string]struct{}{"example.com": {}},
		excludedURLs:             map[string]struct{}{"/favicon": {}},
		httpClient:               &http.Client{},
		exchangeCodeForTokenFunc: ts.exchangeCodeForTokenFunc,
		extractClaimsFunc:        extractClaims,
	}

	ts.tOidc.tokenVerifier = ts.tOidc
	ts.tOidc.jwtVerifier = ts.tOidc
}

// Helper functions used by TraefikOidc
func (ts *TestSuite) exchangeCodeForTokenFunc(code string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"id_token": ts.token,
	}, nil
}

// MockJWKCache implements JWKCacheInterface
type MockJWKCache struct {
	JWKS *JWKSet
	Err  error
}

func (m *MockJWKCache) GetJWKS(jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	return m.JWKS, m.Err
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

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signedContent))
	hashed := hasher.Sum(nil)

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
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
	ts := &TestSuite{t: t}
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
			// Reset token blacklist and cache
			ts.tOidc.tokenBlacklist = NewTokenBlacklist()
			ts.tOidc.tokenCache = NewTokenCache()
			ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Second), 10)

			// Set up the test case
			if tc.blacklist {
				ts.tOidc.tokenBlacklist.Add(tc.token, time.Now().Add(1*time.Hour))
			}

			if tc.rateLimit {
				// Exceed rate limit
				ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Hour), 0)
			}

			if tc.cacheToken {
				ts.tOidc.tokenCache.Set(tc.token, map[string]interface{}{
					"empty": "claim",
				}, 60)
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
	ts := &TestSuite{t: t}
	ts.Setup()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	ts.tOidc.next = nextHandler
	ts.tOidc.name = "test"

	tests := []struct {
		name           string
		requestPath    string
		sessionValues  map[interface{}]interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Excluded URL",
			requestPath:    "/favicon.ico",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Unauthenticated request to protected URL",
			requestPath:    "/protected",
			expectedStatus: http.StatusFound,
		},
		{
			name:        "Authenticated request to protected URL",
			requestPath: "/protected",
			sessionValues: map[interface{}]interface{}{
				"authenticated": true,
				"email":         "user@example.com",
				"id_token":      ts.token,
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:        "Logout URL",
			requestPath: "/logout",
			sessionValues: map[interface{}]interface{}{
				"authenticated": true,
				"email":         "user@example.com",
				"id_token":      ts.token,
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Logged out\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a request
			req := httptest.NewRequest("GET", tc.requestPath, nil)
			req.Header.Set("X-Forwarded-Proto", "http")
			req.Header.Set("X-Forwarded-Host", "localhost")

			// Create a temporary response recorder to save the session
			rrSession := httptest.NewRecorder()

			// Create a session
			session, _ := ts.tOidc.store.New(req, cookieName)
			if tc.sessionValues != nil {
				for k, v := range tc.sessionValues {
					session.Values[k] = v
				}
				session.Save(req, rrSession)
			}

			// Copy session cookie from rrSession to request
			for _, cookie := range rrSession.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Create a response recorder for ServeHTTP
			rr := httptest.NewRecorder()

			// Call ServeHTTP
			ts.tOidc.ServeHTTP(rr, req)

			// Check the response
			if rr.Code != tc.expectedStatus {
				t.Errorf("Test %s: expected status %d, got %d", tc.name, tc.expectedStatus, rr.Code)
			}
			if tc.expectedBody != "" && strings.TrimSpace(rr.Body.String()) != strings.TrimSpace(rr.Body.String()) {
				t.Errorf("Test %s: expected body '%s', got '%s'", tc.name, tc.expectedBody, rr.Body.String())
			}
		})
	}
}

func TestJWKToPEM(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name          string
		jwk           *JWK
		expectError   bool
		errorContains string
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
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name          string
		token         string
		expectError   bool
		errorContains string
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
	ts := &TestSuite{t: t}
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
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name                 string
		queryParams          string
		exchangeCodeForToken func(code string) (map[string]interface{}, error)
		extractClaimsFunc    func(tokenString string) (map[string]interface{}, error)
		expectedStatus       int
	}{
		{
			name:        "Success",
			queryParams: "?code=test-code",
			exchangeCodeForToken: func(code string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"id_token": "test-id-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@example.com",
				}, nil
			},
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Missing Code",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Exchange Code Error",
			queryParams: "?code=test-code",
			exchangeCodeForToken: func(code string) (map[string]interface{}, error) {
				return nil, fmt.Errorf("exchange code error")
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Missing ID Token",
			queryParams: "?code=test-code",
			exchangeCodeForToken: func(code string) (map[string]interface{}, error) {
				return map[string]interface{}{}, nil
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Disallowed Email",
			queryParams: "?code=test-code",
			exchangeCodeForToken: func(code string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"id_token": "test-id-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@disallowed.com",
				}, nil
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new instance for each test to avoid state carryover
			tOidc := &TraefikOidc{
				store:                    sessions.NewCookieStore([]byte("test-secret-key")),
				allowedUserDomains:       map[string]struct{}{"example.com": {}},
				logger:                   NewLogger("info"),
				exchangeCodeForTokenFunc: tc.exchangeCodeForToken,
				extractClaimsFunc:        tc.extractClaimsFunc,
			}

			// Create request and response recorder
			req := httptest.NewRequest("GET", "/callback"+tc.queryParams, nil)
			rr := httptest.NewRecorder()

			// Create session
			session, _ := tOidc.store.New(req, cookieName)
			session.Save(req, rr)

			// Copy session cookie to request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Reset rr for the actual test
			rr = httptest.NewRecorder()

			// Call handleCallback
			tOidc.handleCallback(rr, req)

			// Check response
			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

func TestIsAllowedDomain(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name    string
		email   string
		allowed bool
	}{
		{
			name:    "Allowed domain",
			email:   "user@example.com",
			allowed: true,
		},
		{
			name:    "Disallowed domain",
			email:   "user@notallowed.com",
			allowed: false,
		},
		{
			name:    "Invalid email",
			email:   "invalid-email",
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed := ts.tOidc.isAllowedDomain(tc.email)
			if allowed != tc.allowed {
				t.Errorf("Expected allowed=%v, got %v", tc.allowed, allowed)
			}
		})
	}
}
