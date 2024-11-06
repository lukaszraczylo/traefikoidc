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
		"nonce": "test-nonce",
	})
	if err != nil {
		ts.t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Common TraefikOidc instance
	ts.tOidc = &TraefikOidc{
		issuerURL:          "https://test-issuer.com",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		jwkCache:           ts.mockJWKCache,
		jwksURL:            "https://test-jwks-url.com",
		revocationURL:      "https://revocation-endpoint.com",
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		tokenBlacklist:     NewTokenBlacklist(),
		tokenCache:         NewTokenCache(),
		logger:             NewLogger("info"),
		store:              sessions.NewCookieStore([]byte("test-secret-key")),
		allowedUserDomains: map[string]struct{}{"example.com": {}},
		excludedURLs:       map[string]struct{}{"/favicon": {}},
		httpClient:         &http.Client{},
		extractClaimsFunc:  extractClaims,
		initComplete:       make(chan struct{}),
	}
	close(ts.tOidc.initComplete)
	ts.tOidc.exchangeCodeForTokenFunc = ts.exchangeCodeForTokenFunc
	ts.tOidc.tokenVerifier = ts.tOidc
	ts.tOidc.jwtVerifier = ts.tOidc
}

// Helper functions used by TraefikOidc
func (ts *TestSuite) exchangeCodeForTokenFunc(code string) (*TokenResponse, error) {
	return &TokenResponse{
		IDToken:      ts.token,
		RefreshToken: "test-refresh-token",
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
		exchangeCodeForToken func(code string) (*TokenResponse, error)
		extractClaimsFunc    func(tokenString string) (map[string]interface{}, error)
		sessionSetupFunc     func(session *sessions.Session)
		expectedStatus       int
	}{
		{
			name:        "Success",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusFound,
		},
		{
			name:        "Missing Code",
			queryParams: "",
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Exchange Code Error",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
				return nil, fmt.Errorf("exchange code error")
			},
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Missing ID Token",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Disallowed Email",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
				return &TokenResponse{
					IDToken:      ts.token,
					RefreshToken: "test-refresh-token",
				}, nil
			},
			extractClaimsFunc: func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"email": "user@disallowed.com",
					"nonce": "test-nonce",
				}, nil
			},
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:        "Invalid State Parameter",
			queryParams: "?code=test-code&state=invalid-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Nonce Mismatch",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Missing Nonce in Claims",
			queryParams: "?code=test-code&state=test-csrf-token",
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			sessionSetupFunc: func(session *sessions.Session) {
				session.Values["csrf"] = "test-csrf-token"
				session.Values["nonce"] = "test-nonce"
			},
			expectedStatus: http.StatusInternalServerError,
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
				tokenVerifier:            ts.tOidc.tokenVerifier,
				jwtVerifier:              ts.tOidc.jwtVerifier,
			}

			// Create request and response recorder
			req := httptest.NewRequest("GET", "/callback"+tc.queryParams, nil)
			rr := httptest.NewRecorder()

			// Create session
			session, _ := tOidc.store.New(req, cookieName)
			if tc.sessionSetupFunc != nil {
				tc.sessionSetupFunc(session)
			}
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

func TestOIDCHandler(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	ts.token = "valid.jwt.token"

	tests := []struct {
		name                 string
		queryParams          string
		exchangeCodeForToken func(code string) (*TokenResponse, error)
		extractClaimsFunc    func(tokenString string) (map[string]interface{}, error)
		sessionSetupFunc     func(session *sessions.Session)
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
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
			exchangeCodeForToken: func(code string) (*TokenResponse, error) {
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
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			// Reset token blacklist and cache
			ts.tOidc.tokenBlacklist = NewTokenBlacklist()
			ts.tOidc.tokenCache = NewTokenCache()
			ts.tOidc.limiter = rate.NewLimiter(rate.Every(time.Second), 10)

			// Set up the test case
			if tc.blacklist {
				ts.tOidc.tokenBlacklist.Add(ts.token, time.Now().Add(1*time.Hour))
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
	ts := &TestSuite{t: t}
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
		name           string
		setupSession   func(*sessions.Session)
		endSessionURL  string
		expectedStatus int
		expectedURL    string
		host           string
	}{
		{
			name: "Successful logout with end session endpoint",
			setupSession: func(session *sessions.Session) {
				session.Values["authenticated"] = true
				session.Values["id_token"] = "test.id.token"
				session.Values["refresh_token"] = "test-refresh-token"
				session.Values["access_token"] = "test-access-token"
			},
			endSessionURL:  "https://provider/end-session",
			expectedStatus: http.StatusFound,
			expectedURL:    "https://provider/end-session?id_token_hint=test.id.token&post_logout_redirect_uri=http%3A%2F%2Fexample.com%2F",
			host:           "test-host",
		},
		{
			name: "Successful logout without end session endpoint",
			setupSession: func(session *sessions.Session) {
				session.Values["authenticated"] = true
				session.Values["id_token"] = "test.id.token"
				session.Values["refresh_token"] = "test-refresh-token"
				session.Values["access_token"] = "test-access-token"
			},
			endSessionURL:  "",
			expectedStatus: http.StatusFound,
			expectedURL:    "http://example.com/",
			host:           "test-host",
		},
		{
			name:           "Logout with empty session",
			setupSession:   func(session *sessions.Session) {},
			expectedStatus: http.StatusFound,
			expectedURL:    "http://example.com/",
			host:           "test-host",
		},
		{
			name: "Logout with invalid end session URL",
			setupSession: func(session *sessions.Session) {
				session.Values["authenticated"] = true
				session.Values["id_token"] = "test.id.token"
			},
			endSessionURL:  ":\\invalid-url",
			expectedStatus: http.StatusInternalServerError,
			host:           "test-host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new TraefikOidc instance for each test
			tOidc := &TraefikOidc{
				store:          sessions.NewCookieStore([]byte("test-secret-key")),
				revocationURL:  mockRevocationServer.URL,
				endSessionURL:  tc.endSessionURL,
				scheme:         "http",
				logger:         NewLogger("info"),
				tokenBlacklist: NewTokenBlacklist(),
				httpClient:     &http.Client{},
				clientID:       "test-client-id",
				clientSecret:   "test-client-secret",
				tokenCache:     NewTokenCache(),
				forceHTTPS:     false,
			}

			// Create request with proper headers
			req := httptest.NewRequest("GET", "/logout", nil)
			req.Header.Set("Host", tc.host)

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Get a session
			session, err := tOidc.store.Get(req, cookieName)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Setup session
			tc.setupSession(session)
			session.Save(req, rr)

			// Copy session cookie to request
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

			// Check redirect URL if expected
			if tc.expectedURL != "" {
				location := rr.Header().Get("Location")
				if location != tc.expectedURL {
					t.Errorf("Expected redirect to %q, got %q", tc.expectedURL, location)
				}
			}

			// Verify session is cleared
			newSession, _ := tOidc.store.Get(req, cookieName)
			if len(newSession.Values) > 0 {
				t.Error("Session was not cleared")
			}
			if newSession.Options.MaxAge != -1 {
				t.Error("Session MaxAge was not set to -1")
			}

			// Check token blacklist
			if refreshToken, ok := session.Values["refresh_token"].(string); ok && refreshToken != "" {
				if !tOidc.tokenBlacklist.IsBlacklisted(refreshToken) {
					t.Error("Refresh token was not blacklisted")
				}
			}
			if accessToken, ok := session.Values["access_token"].(string); ok && accessToken != "" {
				if !tOidc.tokenBlacklist.IsBlacklisted(accessToken) {
					t.Error("Access token was not blacklisted")
				}
			}
		})
	}
}

// TestRevokeTokenWithProvider tests the token revocation with provider
func TestRevokeTokenWithProvider(t *testing.T) {
	ts := &TestSuite{t: t}
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
	ts := &TestSuite{t: t}
	ts.Setup()

	token := "test.token.with.claims"
	claims := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}

	// Test token revocation
	t.Run("Token revocation", func(t *testing.T) {
		// Create a new instance for this specific test
		tOidc := &TraefikOidc{
			tokenBlacklist: NewTokenBlacklist(),
			tokenCache:     NewTokenCache(),
		}

		// Cache the token
		tOidc.tokenCache.Set(token, claims, time.Hour)

		// Revoke the token
		tOidc.RevokeToken(token)

		// Verify token was removed from cache
		if _, exists := tOidc.tokenCache.Get(token); exists {
			t.Error("Token was not removed from cache")
		}

		// Verify token was added to blacklist
		if !tOidc.tokenBlacklist.IsBlacklisted(token) {
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
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name         string
		setupSession func(*sessions.Session)
		expectedPath string
	}{
		{
			name: "Basic expired token",
			setupSession: func(session *sessions.Session) {
				session.Values["authenticated"] = true
				session.Values["id_token"] = "expired.token"
				session.Values["email"] = "test@example.com"
			},
			expectedPath: "/original/path",
		},
		{
			name: "Session with additional values",
			setupSession: func(session *sessions.Session) {
				session.Values["authenticated"] = true
				session.Values["id_token"] = "expired.token"
				session.Values["custom_value"] = "should-be-cleared"
			},
			expectedPath: "/another/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new TraefikOidc instance for each test
			tOidc := &TraefikOidc{
				store:         sessions.NewCookieStore([]byte("test-secret-key")),
				logger:        NewLogger("info"),
				redirectURL:   "http://example.com/callback",
				tokenVerifier: ts.tOidc.tokenVerifier,
				jwtVerifier:   ts.tOidc.jwtVerifier,
				initComplete:  make(chan struct{}),
				// Add this initialization of initiateAuthenticationFunc
				initiateAuthenticationFunc: func(rw http.ResponseWriter, req *http.Request, session *sessions.Session, redirectURL string) {
					// Mock implementation for test
					http.Redirect(rw, req, "/login", http.StatusFound)
				},
			}
			close(tOidc.initComplete)

			// Create request
			req := httptest.NewRequest("GET", tc.expectedPath, nil)
			rr := httptest.NewRecorder()

			// Get session
			session, _ := tOidc.store.New(req, cookieName)
			tc.setupSession(session)

			// Handle expired token
			tOidc.handleExpiredToken(rr, req, session)

			// Verify session is cleaned
			if len(session.Values) != 3 { // Should only have csrf, incoming_path, and nonce
				t.Errorf("Expected 3 session values, got %d", len(session.Values))
			}

			// Verify required values are set
			if _, ok := session.Values["csrf"].(string); !ok {
				t.Error("CSRF token not set")
			}
			if path, ok := session.Values["incoming_path"].(string); !ok || path != tc.expectedPath {
				t.Errorf("Expected path %s, got %s", tc.expectedPath, path)
			}
			if _, ok := session.Values["nonce"].(string); !ok {
				t.Error("Nonce not set")
			}

			// Verify session options
			if session.Options.MaxAge != defaultSessionOptions.MaxAge {
				t.Error("Session MaxAge not set correctly")
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
	ts := &TestSuite{t: t}
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
