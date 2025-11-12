package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFramework provides a unified testing framework for the OIDC middleware
type TestFramework struct {
	t          *testing.T
	server     *httptest.Server
	oidc       *TraefikOidc
	config     *Config
	cleanup    []func()
	mocks      *TestMocks
	fixtures   *TestFixtures
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	mu         sync.Mutex
}

// TestMocks contains all mock implementations
type TestMocks struct {
	JWKCache       *MockJWKCache
	TokenVerifier  *MockTokenVerifier
	TokenExchanger *MockTokenExchanger
	JWTVerifier    *MockJWTVerifier
	HTTPClient     *http.Client
	Provider       interface{}
}

// TestFixtures contains reusable test data
type TestFixtures struct {
	ValidJWT      string
	ExpiredJWT    string
	InvalidJWT    string
	RefreshToken  string
	AccessToken   string
	IDToken       string
	Claims        map[string]interface{}
	UserEmail     string
	UserSub       string
	ClientID      string
	ClientSecret  string
	ProviderURL   string
	CallbackURL   string
	EncryptionKey string
	Nonce         string
	State         string
	CodeVerifier  string
	CodeChallenge string
	AuthCode      string
}

// NewTestFramework creates a new test framework instance
func NewTestFramework(t *testing.T) *TestFramework {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tf := &TestFramework{
		t:          t,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		mocks:      &TestMocks{},
		fixtures:   generateTestFixtures(),
		cleanup:    make([]func(), 0),
	}

	// Register cleanup
	t.Cleanup(tf.Cleanup)

	return tf
}

// generateTestFixtures creates standard test data
func generateTestFixtures() *TestFixtures {
	return &TestFixtures{
		UserEmail:     "test@example.com",
		UserSub:       "test-user-123",
		ClientID:      "test-client-id",
		ClientSecret:  "test-client-secret",
		ProviderURL:   "https://provider.example.com",
		CallbackURL:   "/callback",
		EncryptionKey: "test-encryption-key-32-bytes-long!!",
		Nonce:         "test-nonce-123",
		State:         "test-state-456",
		AuthCode:      "test-auth-code",
		RefreshToken:  "test-refresh-token",
		AccessToken:   "test-access-token",
		Claims: map[string]interface{}{
			"email": "test@example.com",
			"sub":   "test-user-123",
			"name":  "Test User",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		},
	}
}

// SetupOIDC creates a configured OIDC middleware instance for testing
func (tf *TestFramework) SetupOIDC(customConfig ...*Config) *TraefikOidc {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	config := tf.GetDefaultConfig()
	if len(customConfig) > 0 && customConfig[0] != nil {
		config = customConfig[0]
	}

	tf.config = config

	// Create OIDC instance
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	})

	oidc, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		tf.t.Fatalf("Failed to create OIDC middleware: %v", err)
	}

	tf.oidc = oidc.(*TraefikOidc)

	// Override with mocks if configured
	if tf.mocks.TokenVerifier != nil {
		tf.oidc.tokenVerifier = tf.mocks.TokenVerifier
	}
	if tf.mocks.TokenExchanger != nil {
		tf.oidc.tokenExchanger = tf.mocks.TokenExchanger
	}

	tf.AddCleanup(func() {
		if tf.oidc != nil {
			tf.oidc.Close()
		}
	})

	return tf.oidc
}

// SetupMockProvider creates a mock OIDC provider server
func (tf *TestFramework) SetupMockProvider() *httptest.Server {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	mux := http.NewServeMux()

	// Well-known configuration endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer":                 tf.fixtures.ProviderURL,
			"authorization_endpoint": tf.fixtures.ProviderURL + "/authorize",
			"token_endpoint":         tf.fixtures.ProviderURL + "/token",
			"jwks_uri":               tf.fixtures.ProviderURL + "/jwks",
			"userinfo_endpoint":      tf.fixtures.ProviderURL + "/userinfo",
			"end_session_endpoint":   tf.fixtures.ProviderURL + "/logout",
		}
		json.NewEncoder(w).Encode(metadata)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := tf.GenerateJWKS()
		json.NewEncoder(w).Encode(jwks)
	})

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"access_token":  tf.fixtures.AccessToken,
			"refresh_token": tf.fixtures.RefreshToken,
			"id_token":      tf.GenerateJWT(tf.fixtures.Claims),
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		json.NewEncoder(w).Encode(response)
	})

	// UserInfo endpoint
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tf.fixtures.Claims)
	})

	server := httptest.NewServer(mux)
	tf.server = server
	tf.fixtures.ProviderURL = server.URL

	tf.AddCleanup(server.Close)

	return server
}

// GetDefaultConfig returns a default test configuration
func (tf *TestFramework) GetDefaultConfig() *Config {
	return &Config{
		ProviderURL:          tf.fixtures.ProviderURL,
		ClientID:             tf.fixtures.ClientID,
		ClientSecret:         tf.fixtures.ClientSecret,
		CallbackURL:          tf.fixtures.CallbackURL,
		SessionEncryptionKey: tf.fixtures.EncryptionKey,
		LogLevel:             "debug",
		ForceHTTPS:           false,
		Scopes:               []string{"openid", "email", "profile"},
		RateLimit:            100,
	}
}

// GenerateJWT creates a test JWT with the given claims
func (tf *TestFramework) GenerateJWT(claims map[string]interface{}) string {
	tokenString, _ := createTestJWT(tf.privateKey, "RS256", "test-key", claims)
	return tokenString
}

// GenerateExpiredJWT creates an expired JWT for testing
func (tf *TestFramework) GenerateExpiredJWT() string {
	claims := make(map[string]interface{})
	for k, v := range tf.fixtures.Claims {
		claims[k] = v
	}
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	return tf.GenerateJWT(claims)
}

// GenerateInvalidJWT creates an invalid JWT for testing
func (tf *TestFramework) GenerateInvalidJWT() string {
	return "invalid.jwt.token"
}

// GenerateJWKS creates a JWKS response
func (tf *TestFramework) GenerateJWKS() map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(tf.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-id",
				"n":   n,
				"e":   e,
				"alg": "RS256",
			},
		},
	}
}

// CreateRequest creates a test HTTP request
func (tf *TestFramework) CreateRequest(method, path string, body ...string) *http.Request {
	var bodyReader *strings.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(body[0])
	} else {
		bodyReader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("User-Agent", "test-agent")
	return req
}

// CreateAuthenticatedRequest creates a request with session cookies
func (tf *TestFramework) CreateAuthenticatedRequest(method, path string) (*http.Request, *httptest.ResponseRecorder) {
	req := tf.CreateRequest(method, path)
	rw := httptest.NewRecorder()

	// Create session
	sessionManager, err := NewSessionManager(
		tf.fixtures.EncryptionKey,
		false,
		"",
		"",
		tf.oidc.logger,
	)
	if err != nil {
		tf.t.Fatalf("Error: %v", err)
	}

	session, err := sessionManager.GetSession(req)
	if err != nil {
		tf.t.Fatalf("Error: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetEmail(tf.fixtures.UserEmail)
	session.SetAccessToken(tf.fixtures.AccessToken)
	session.SetRefreshToken(tf.fixtures.RefreshToken)
	session.SetIDToken(tf.GenerateJWT(tf.fixtures.Claims))

	err = session.Save(req, rw)
	if err != nil {
		tf.t.Fatalf("Error: %v", err)
	}

	// Copy cookies to request
	for _, cookie := range rw.Result().Cookies() {
		req.AddCookie(cookie)
	}

	return req, httptest.NewRecorder()
}

// CreateCallbackRequest creates an OAuth callback request
func (tf *TestFramework) CreateCallbackRequest() *http.Request {
	values := url.Values{
		"code":  {tf.fixtures.AuthCode},
		"state": {tf.fixtures.State},
	}

	req := tf.CreateRequest("GET", tf.fixtures.CallbackURL+"?"+values.Encode())

	// Add session with state
	sessionManager, _ := NewSessionManager(
		tf.fixtures.EncryptionKey,
		false,
		"",
		"",
		tf.oidc.logger,
	)

	session, _ := sessionManager.GetSession(req)
	session.SetCSRF(tf.fixtures.State)
	session.SetNonce(tf.fixtures.Nonce)

	rw := httptest.NewRecorder()
	session.Save(req, rw)

	for _, cookie := range rw.Result().Cookies() {
		req.AddCookie(cookie)
	}

	return req
}

// AssertResponse validates HTTP response
func (tf *TestFramework) AssertResponse(rw *httptest.ResponseRecorder, expectedStatus int, contains ...string) {
	if rw.Code != expectedStatus {
		tf.t.Errorf("Unexpected status code: got %d, want %d", rw.Code, expectedStatus)
	}

	body := rw.Body.String()
	for _, expected := range contains {
		if !strings.Contains(body, expected) {
			tf.t.Errorf("Response body missing expected content: %s", expected)
		}
	}
}

// AssertRedirect validates redirect response
func (tf *TestFramework) AssertRedirect(rw *httptest.ResponseRecorder, expectedLocation string) {
	if rw.Code != http.StatusFound {
		tf.t.Errorf("Expected redirect status, got %d", rw.Code)
	}
	location := rw.Header().Get("Location")
	if strings.HasPrefix(expectedLocation, "http") {
		if location != expectedLocation {
			tf.t.Errorf("Expected location %s, got %s", expectedLocation, location)
		}
	} else {
		if !strings.Contains(location, expectedLocation) {
			tf.t.Errorf("Location should contain %s, got %s", expectedLocation, location)
		}
	}
}

// AssertCookie validates response cookies
func (tf *TestFramework) AssertCookie(rw *httptest.ResponseRecorder, name string, exists bool) {
	cookies := rw.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == name {
			found = true
			break
		}
	}

	if exists {
		if !found {
			tf.t.Errorf("Cookie %s not found", name)
		}
	} else {
		if found {
			tf.t.Errorf("Cookie %s should not exist", name)
		}
	}
}

// AddCleanup registers a cleanup function
func (tf *TestFramework) AddCleanup(fn func()) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	tf.cleanup = append(tf.cleanup, fn)
}

// Cleanup runs all registered cleanup functions
func (tf *TestFramework) Cleanup() {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	for i := len(tf.cleanup) - 1; i >= 0; i-- {
		if tf.cleanup[i] != nil {
			tf.cleanup[i]()
		}
	}

	tf.cleanup = nil
}

// RunSubtest runs a subtest with the framework
func (tf *TestFramework) RunSubtest(name string, fn func()) {
	tf.t.Run(name, func(t *testing.T) {
		// Create sub-framework with shared resources
		subTF := &TestFramework{
			t:          t,
			server:     tf.server,
			oidc:       tf.oidc,
			config:     tf.config,
			mocks:      tf.mocks,
			fixtures:   tf.fixtures,
			privateKey: tf.privateKey,
			publicKey:  tf.publicKey,
			cleanup:    make([]func(), 0),
		}

		defer subTF.Cleanup()

		// Set the current test framework for the function
		currentTestFramework = subTF
		fn()
		currentTestFramework = nil
	})
}

var currentTestFramework *TestFramework

// GetTestFramework returns the current test framework (for use in test functions)
func GetTestFramework() *TestFramework {
	return currentTestFramework
}

// Mock implementations are defined in main_test.go and other test files
// The test framework uses the existing mock types

// TestScenarios provides common test scenarios

// TestScenario represents a test scenario
type TestScenario struct {
	Name           string
	Setup          func(*TestFramework)
	Request        func(*TestFramework) *http.Request
	ExpectedStatus int
	ExpectedBody   string
	Validate       func(*TestFramework, *httptest.ResponseRecorder)
}

// RunScenarios executes a set of test scenarios
func (tf *TestFramework) RunScenarios(scenarios []TestScenario) {
	for _, scenario := range scenarios {
		tf.RunSubtest(scenario.Name, func() {
			// Setup
			if scenario.Setup != nil {
				scenario.Setup(tf)
			}

			// Create request
			req := scenario.Request(tf)
			rw := httptest.NewRecorder()

			// Execute
			tf.oidc.ServeHTTP(rw, req)

			// Validate
			if scenario.ExpectedStatus > 0 {
				tf.AssertResponse(rw, scenario.ExpectedStatus)
			}

			if scenario.ExpectedBody != "" {
				tf.AssertResponse(rw, rw.Code, scenario.ExpectedBody)
			}

			if scenario.Validate != nil {
				scenario.Validate(tf, rw)
			}
		})
	}
}
