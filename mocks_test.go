package traefikoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/sessions"
)

// MockOAuthProvider simulates an OAuth/OIDC provider for testing
type MockOAuthProvider struct {
	TokenExchangeFunc   func(grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error)
	LastRequest         *http.Request
	JWKSResponseFunc    func() ([]byte, error)
	RevokeTokenFunc     func(token, tokenType string) error
	RefreshTokenFunc    func(refreshToken string) (*TokenResponse, error)
	EndSessionEndpoint  string
	TokenEndpoint       string
	RevokeEndpoint      string
	JWKSEndpoint        string
	AuthEndpoint        string
	RequestHistory      []*http.Request
	LastRequestBody     []byte
	TimeoutDuration     time.Duration
	ResponseDelay       time.Duration
	mu                  sync.Mutex
	RequestCount        int32
	SimulateServerError bool
	SimulateRateLimit   bool
	SimulateTimeout     bool
}

// NewMockOAuthProvider creates a new mock OAuth provider with default endpoints
func NewMockOAuthProvider() *MockOAuthProvider {
	return &MockOAuthProvider{
		TokenEndpoint:      "https://mock-provider.example.com/token",
		AuthEndpoint:       "https://mock-provider.example.com/auth",
		JWKSEndpoint:       "https://mock-provider.example.com/.well-known/jwks.json",
		RevokeEndpoint:     "https://mock-provider.example.com/revoke",
		EndSessionEndpoint: "https://mock-provider.example.com/logout",
		TimeoutDuration:    30 * time.Second,
	}
}

// ServeHTTP handles HTTP requests to the mock provider
func (m *MockOAuthProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&m.RequestCount, 1)

	m.mu.Lock()
	m.LastRequest = r
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		m.LastRequestBody = body
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	m.RequestHistory = append(m.RequestHistory, r)
	m.mu.Unlock()

	// Simulate delays
	if m.ResponseDelay > 0 {
		time.Sleep(m.ResponseDelay)
	}

	// Simulate timeout
	if m.SimulateTimeout {
		time.Sleep(m.TimeoutDuration)
		return
	}

	// Simulate rate limiting
	if m.SimulateRateLimit {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "rate_limit_exceeded"}`))
		return
	}

	// Simulate server error
	if m.SimulateServerError {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal_server_error"}`))
		return
	}

	// Route to appropriate handler
	switch {
	case strings.Contains(r.URL.Path, "/token"):
		m.handleTokenRequest(w, r)
	case strings.Contains(r.URL.Path, "/jwks"):
		m.handleJWKSRequest(w, r)
	case strings.Contains(r.URL.Path, "/revoke"):
		m.handleRevokeRequest(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *MockOAuthProvider) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(body))

	grantType := values.Get("grant_type")

	var response *TokenResponse
	var err error

	if grantType == "authorization_code" {
		code := values.Get("code")
		redirectURL := values.Get("redirect_uri")
		codeVerifier := values.Get("code_verifier")

		if m.TokenExchangeFunc != nil {
			response, err = m.TokenExchangeFunc(grantType, code, redirectURL, codeVerifier)
		} else {
			// Default successful response
			response = &TokenResponse{
				AccessToken:  "mock_access_token",
				IDToken:      "mock_id_token",
				RefreshToken: "mock_refresh_token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}
		}
	} else if grantType == "refresh_token" {
		refreshToken := values.Get("refresh_token")

		if m.RefreshTokenFunc != nil {
			response, err = m.RefreshTokenFunc(refreshToken)
		} else {
			// Default successful refresh response
			response = &TokenResponse{
				AccessToken:  "new_mock_access_token",
				IDToken:      "new_mock_id_token",
				RefreshToken: "new_mock_refresh_token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}
		}
	}

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (m *MockOAuthProvider) handleJWKSRequest(w http.ResponseWriter, r *http.Request) {
	var response []byte
	var err error

	if m.JWKSResponseFunc != nil {
		response, err = m.JWKSResponseFunc()
	} else {
		// Default JWKS response
		response = []byte(`{
			"keys": [
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "test-key-1",
					"n": "test-modulus",
					"e": "AQAB"
				}
			]
		}`)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (m *MockOAuthProvider) handleRevokeRequest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(body))

	token := values.Get("token")
	tokenType := values.Get("token_type_hint")

	if m.RevokeTokenFunc != nil {
		if err := m.RevokeTokenFunc(token, tokenType); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_token",
			})
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// GetRequestCount returns the number of requests received
func (m *MockOAuthProvider) GetRequestCount() int {
	return int(atomic.LoadInt32(&m.RequestCount))
}

// Reset resets the mock provider state
func (m *MockOAuthProvider) Reset() {
	atomic.StoreInt32(&m.RequestCount, 0)
	m.mu.Lock()
	m.LastRequest = nil
	m.LastRequestBody = nil
	m.RequestHistory = nil
	m.mu.Unlock()
	m.SimulateTimeout = false
	m.SimulateRateLimit = false
	m.SimulateServerError = false
}

// MockSessionManager implements a mock session manager for testing
type MockSessionManager struct {
	Sessions          map[string]*SessionData
	GetSessionFunc    func(r *http.Request) (*SessionData, error)
	SaveSessionFunc   func(r *http.Request, w http.ResponseWriter, session *SessionData) error
	DeleteSessionFunc func(r *http.Request, w http.ResponseWriter) error
	mu                sync.RWMutex
	GetCallCount      int32
	SaveCallCount     int32
	DeleteCallCount   int32
	SimulateError     bool
	SimulateNotFound  bool
}

// NewMockSessionManager creates a new mock session manager
func NewMockSessionManager() *MockSessionManager {
	return &MockSessionManager{
		Sessions: make(map[string]*SessionData),
	}
}

// GetSession retrieves a session
func (m *MockSessionManager) GetSession(r *http.Request) (*SessionData, error) {
	atomic.AddInt32(&m.GetCallCount, 1)

	if m.GetSessionFunc != nil {
		return m.GetSessionFunc(r)
	}

	if m.SimulateError {
		return nil, errors.New("session error")
	}

	if m.SimulateNotFound {
		return nil, nil
	}

	// Default implementation using a simple cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, nil
	}

	m.mu.RLock()
	session, exists := m.Sessions[cookie.Value]
	m.mu.RUnlock()

	if !exists {
		return nil, nil
	}

	return session, nil
}

// SaveSession saves a session
func (m *MockSessionManager) SaveSession(r *http.Request, w http.ResponseWriter, session *SessionData) error {
	atomic.AddInt32(&m.SaveCallCount, 1)

	if m.SaveSessionFunc != nil {
		return m.SaveSessionFunc(r, w, session)
	}

	if m.SimulateError {
		return errors.New("save error")
	}

	// Generate session ID
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())

	m.mu.Lock()
	m.Sessions[sessionID] = session
	m.mu.Unlock()

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// DeleteSession deletes a session
func (m *MockSessionManager) DeleteSession(r *http.Request, w http.ResponseWriter) error {
	atomic.AddInt32(&m.DeleteCallCount, 1)

	if m.DeleteSessionFunc != nil {
		return m.DeleteSessionFunc(r, w)
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}

	m.mu.Lock()
	delete(m.Sessions, cookie.Value)
	m.mu.Unlock()

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})

	return nil
}

// Reset resets the mock session manager
func (m *MockSessionManager) Reset() {
	m.mu.Lock()
	m.Sessions = make(map[string]*SessionData)
	m.mu.Unlock()
	atomic.StoreInt32(&m.GetCallCount, 0)
	atomic.StoreInt32(&m.SaveCallCount, 0)
	atomic.StoreInt32(&m.DeleteCallCount, 0)
	m.SimulateError = false
	m.SimulateNotFound = false
}

// MockHTTPClient implements a mock HTTP client for testing
type MockHTTPClient struct {
	ResponseFunc      func(req *http.Request) (*http.Response, error)
	DefaultHeaders    map[string]string
	DefaultBody       string
	Requests          []*http.Request
	RequestBodies     [][]byte
	DefaultStatusCode int
	TimeoutDuration   time.Duration
	mu                sync.Mutex
	SimulateTimeout   bool
	SimulateError     bool
}

// NewMockHTTPClient creates a new mock HTTP client
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		DefaultStatusCode: http.StatusOK,
		DefaultHeaders:    make(map[string]string),
		TimeoutDuration:   30 * time.Second,
	}
}

// Do executes a mock HTTP request
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.Requests = append(m.Requests, req)

	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		m.RequestBodies = append(m.RequestBodies, body)
		req.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	m.mu.Unlock()

	// Simulate timeout
	if m.SimulateTimeout {
		ctx, cancel := context.WithTimeout(req.Context(), m.TimeoutDuration)
		defer cancel()
		<-ctx.Done()
		return nil, context.DeadlineExceeded
	}

	// Simulate error
	if m.SimulateError {
		return nil, errors.New("http client error")
	}

	// Use custom response function if provided
	if m.ResponseFunc != nil {
		return m.ResponseFunc(req)
	}

	// Default response
	resp := &http.Response{
		StatusCode: m.DefaultStatusCode,
		Header:     make(http.Header),
		Request:    req,
	}

	// Set headers
	for k, v := range m.DefaultHeaders {
		resp.Header.Set(k, v)
	}

	// Set body
	if m.DefaultBody != "" {
		resp.Body = io.NopCloser(strings.NewReader(m.DefaultBody))
		resp.ContentLength = int64(len(m.DefaultBody))
	} else {
		resp.Body = io.NopCloser(strings.NewReader(""))
	}

	return resp, nil
}

// Reset resets the mock HTTP client
func (m *MockHTTPClient) Reset() {
	m.mu.Lock()
	m.Requests = nil
	m.RequestBodies = nil
	m.mu.Unlock()
	m.SimulateTimeout = false
	m.SimulateError = false
}

// GetRequestCount returns the number of requests made
func (m *MockHTTPClient) GetRequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Requests)
}

// Note: MockTokenExchanger is already defined in main_test.go
// These mock types are provided for additional testing scenarios

// CreateTestHTTPServer creates a test HTTP server with the given handler
func CreateTestHTTPServer(handler http.Handler) *httptest.Server {
	return httptest.NewServer(handler)
}

// CreateTestHTTPSServer creates a test HTTPS server with the given handler
func CreateTestHTTPSServer(handler http.Handler) *httptest.Server {
	return httptest.NewTLSServer(handler)
}

// CreateMockSessionData creates a mock SessionData for testing
func CreateMockSessionData() *SessionData {
	return &SessionData{
		mainSession:        nil,
		accessSession:      nil,
		refreshSession:     nil,
		idTokenSession:     nil,
		accessTokenChunks:  make(map[int]*sessions.Session),
		refreshTokenChunks: make(map[int]*sessions.Session),
		idTokenChunks:      make(map[int]*sessions.Session),
	}
}

// MockRoundTripper implements http.RoundTripper for testing
type MockRoundTripper struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
	Requests      []*http.Request
	mu            sync.Mutex
}

// RoundTrip executes a mock HTTP round trip
func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.Requests = append(m.Requests, req)
	m.mu.Unlock()

	if m.RoundTripFunc != nil {
		return m.RoundTripFunc(req)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// Reset resets the mock round tripper
func (m *MockRoundTripper) Reset() {
	m.mu.Lock()
	m.Requests = nil
	m.mu.Unlock()
}
