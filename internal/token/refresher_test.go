//go:build !yaegi

package token

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Mock implementations for refresher tests
type mockSessionManager struct{}

func (m *mockSessionManager) GetSession(sessionID string) (SessionDataInterface, error) {
	return nil, nil
}

func (m *mockSessionManager) SaveSession(session SessionDataInterface) error {
	return nil
}

type mockSessionData struct {
	idToken      string
	accessToken  string
	refreshToken string
	idExpiry     time.Time
	accessExpiry time.Time
	saveErr      error
}

func (m *mockSessionData) GetIDToken() string {
	return m.idToken
}

func (m *mockSessionData) GetAccessToken() string {
	return m.accessToken
}

func (m *mockSessionData) GetRefreshToken() string {
	return m.refreshToken
}

func (m *mockSessionData) GetIDTokenExpiry() time.Time {
	return m.idExpiry
}

func (m *mockSessionData) GetAccessTokenExpiry() time.Time {
	return m.accessExpiry
}

func (m *mockSessionData) SetTokens(idToken, accessToken, refreshToken string, idExp, accessExp time.Time) {
	m.idToken = idToken
	m.accessToken = accessToken
	m.refreshToken = refreshToken
	m.idExpiry = idExp
	m.accessExpiry = accessExp
}

func (m *mockSessionData) SetIDToken(token string, expiry time.Time) {
	m.idToken = token
	m.idExpiry = expiry
}

func (m *mockSessionData) SetAccessToken(token string, expiry time.Time) {
	m.accessToken = token
	m.accessExpiry = expiry
}

func (m *mockSessionData) SetRefreshToken(token string) {
	m.refreshToken = token
}

func (m *mockSessionData) SaveToCache() error {
	return m.saveErr
}

type mockTokenVerifier struct {
	shouldFail bool
}

func (m *mockTokenVerifier) VerifyToken(token string) error {
	if m.shouldFail {
		return fmt.Errorf("token verification failed")
	}
	return nil
}

// Refresher tests
func TestNewRefresher(t *testing.T) {
	refresher := NewRefresher(
		"client-id",
		"client-secret",
		"https://provider.example.com/token",
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	if refresher == nil {
		t.Fatal("Expected NewRefresher to return non-nil")
	}

	if refresher.clientID != "client-id" {
		t.Error("Expected clientID to be set")
	}

	if refresher.clientSecret != "client-secret" {
		t.Error("Expected clientSecret to be set")
	}

	if refresher.tokenURL != "https://provider.example.com/token" {
		t.Error("Expected tokenURL to be set")
	}
}

func TestRefresher_RefreshToken_NilSession(t *testing.T) {
	refresher := NewRefresher(
		"client-id",
		"client-secret",
		"https://provider.example.com/token",
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	result := refresher.RefreshToken(nil, nil, nil)
	if result {
		t.Error("Expected RefreshToken to return false for nil session")
	}
}

func TestRefresher_RefreshToken_NoRefreshToken(t *testing.T) {
	refresher := NewRefresher(
		"client-id",
		"client-secret",
		"https://provider.example.com/token",
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	session := &mockSessionData{
		refreshToken: "", // No refresh token
	}

	result := refresher.RefreshToken(nil, nil, session)
	if result {
		t.Error("Expected RefreshToken to return false when no refresh token available")
	}
}

func TestRefresher_ExchangeToken_UnsupportedGrantType(t *testing.T) {
	refresher := NewRefresher(
		"client-id",
		"client-secret",
		"https://provider.example.com/token",
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	_, err := refresher.exchangeToken("unsupported_grant", "token", "", "")
	if err == nil {
		t.Error("Expected error for unsupported grant type")
	}

	if err.Error() != "unsupported grant type: unsupported_grant" {
		t.Errorf("Expected unsupported grant type error, got: %v", err)
	}
}

func TestRefresher_ExchangeToken_RefreshToken_RequestCreation(t *testing.T) {
	// Test with valid refresh_token grant type but invalid URL to test request creation
	refresher := NewRefresher(
		"client-id",
		"client-secret",
		"://invalid-url", // Invalid URL
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	_, err := refresher.exchangeToken("refresh_token", "refresh-token-value", "", "")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestRefresher_ExchangeToken_AuthorizationCode_WithPKCE(t *testing.T) {
	// Create a test server that verifies the request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}

		// Verify PKCE parameters are included
		if r.FormValue("code_verifier") != "test-verifier" {
			t.Error("Expected code_verifier to be included")
		}

		if r.FormValue("code") != "auth-code" {
			t.Error("Expected authorization code to be included")
		}

		if r.FormValue("grant_type") != "authorization_code" {
			t.Error("Expected grant_type to be authorization_code")
		}

		// Return valid token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"test-access","id_token":"test-id","expires_in":3600}`))
	}))
	defer server.Close()

	refresher := NewRefresher(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	resp, err := refresher.exchangeToken("authorization_code", "auth-code", "https://callback.example.com", "test-verifier")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.AccessToken != "test-access" {
		t.Errorf("Expected access token 'test-access', got '%s'", resp.AccessToken)
	}

	if resp.IDToken != "test-id" {
		t.Errorf("Expected ID token 'test-id', got '%s'", resp.IDToken)
	}

	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expires_in 3600, got %d", resp.ExpiresIn)
	}
}

func TestRefresher_ExchangeToken_HTTPError(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()

	refresher := NewRefresher(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	_, err := refresher.exchangeToken("refresh_token", "bad-token", "", "")
	if err == nil {
		t.Error("Expected error for HTTP 401 response")
	}
}

func TestRefresher_ExchangeToken_InvalidJSON(t *testing.T) {
	// Create a test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	refresher := NewRefresher(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	_, err := refresher.exchangeToken("refresh_token", "token", "", "")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
}

func TestRefresher_GetNewTokenWithRefreshToken(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer server.Close()

	refresher := NewRefresher(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		&mockMetrics{},
		&mockSessionManager{},
		newMockCache(),
		&mockTokenVerifier{},
	)

	resp, err := refresher.GetNewTokenWithRefreshToken("old-refresh")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.AccessToken != "new-access" {
		t.Error("Expected new access token")
	}

	if resp.RefreshToken != "new-refresh" {
		t.Error("Expected new refresh token")
	}
}
