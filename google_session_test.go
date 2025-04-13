package traefikoidc

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// MockTokenVerifier implements the TokenVerifier interface for testing
type MockTokenVerifier struct {
	VerifyFunc func(token string) error
}

func (m *MockTokenVerifier) VerifyToken(token string) error {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(token)
	}
	return nil
}

func TestGoogleOIDCRefreshTokenHandling(t *testing.T) {
	// Create a mocked TraefikOidc instance that simulates Google provider behavior
	mockLogger := NewLogger("debug")

	// Create a test instance with a Google-like issuer URL
	tOidc := &TraefikOidc{
		issuerURL:          "https://accounts.google.com",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		logger:             mockLogger,
		scopes:             []string{"openid", "profile", "email"},
		refreshGracePeriod: 60,
	}

	// Create a session manager
	sessionManager, _ := NewSessionManager("0123456789abcdef0123456789abcdef", true, mockLogger)
	tOidc.sessionManager = sessionManager

	t.Run("Google provider detection adds required parameters", func(t *testing.T) {
		// Test buildAuthURL to ensure it adds offline_access and prompt=consent for Google
		authURL := tOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Check that offline_access scope was added
		if !strings.Contains(authURL, "scope=") || !strings.Contains(authURL, "offline_access") {
			t.Errorf("offline_access scope not added to Google auth URL: %s", authURL)
		}

		// Check that prompt=consent was added
		if !strings.Contains(authURL, "prompt=consent") {
			t.Errorf("prompt=consent not added to Google auth URL: %s", authURL)
		}
	})

	t.Run("Non-Google provider doesn't add Google-specific params", func(t *testing.T) {
		// Create a test instance with a non-Google issuer URL
		nonGoogleOidc := &TraefikOidc{
			issuerURL:    "https://auth.example.com",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			logger:       mockLogger,
			scopes:       []string{"openid", "profile", "email"},
		}

		// Test buildAuthURL without Google-specific parameters
		authURL := nonGoogleOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Check that prompt=consent is not automatically added
		if strings.Contains(authURL, "prompt=consent") {
			t.Errorf("prompt=consent added to non-Google auth URL: %s", authURL)
		}
	})

	t.Run("Session refresh with Google provider", func(t *testing.T) {
		// Create a request and response recorder
		req := httptest.NewRequest("GET", "/test", nil)
		rw := httptest.NewRecorder()

		// Create a session and set a refresh token
		session, _ := sessionManager.GetSession(req)
		session.SetAuthenticated(true)
		session.SetEmail("test@example.com")
		session.SetAccessToken("old-access-token")
		session.SetRefreshToken("valid-refresh-token")

		// Create a mock token exchanger that simulates Google's behavior
		mockTokenExchanger := &MockTokenExchanger{
			RefreshTokenFunc: func(refreshToken string) (*TokenResponse, error) {
				// Check that the refresh token is passed correctly
				if refreshToken != "valid-refresh-token" {
					t.Errorf("Incorrect refresh token passed: %s", refreshToken)
					return nil, fmt.Errorf("invalid token")
				}

				// Return a simulated Google token response with a new access token
				// but without a new refresh token (Google doesn't always return a new refresh token)
				return &TokenResponse{
					IDToken:      "new-id-token-from-google",
					AccessToken:  "new-access-token-from-google",
					RefreshToken: "", // Google often doesn't return a new refresh token
					ExpiresIn:    3600,
				}, nil
			},
		}

		// Set the mock token exchanger
		tOidc.tokenExchanger = mockTokenExchanger

		// Create a struct that implements the TokenVerifier interface
		tOidc.tokenVerifier = &MockTokenVerifier{
			VerifyFunc: func(token string) error {
				return nil
			},
		}

		tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
			// Return mock claims
			return map[string]interface{}{
				"email": "test@example.com",
				"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			}, nil
		}

		// Attempt to refresh the token
		refreshed := tOidc.refreshToken(rw, req, session)

		// Verify the refresh was successful
		if !refreshed {
			t.Error("Token refresh failed for Google provider")
		}

		// Check that we kept the original refresh token since Google didn't provide a new one
		if session.GetRefreshToken() != "valid-refresh-token" {
			t.Errorf("Original refresh token not preserved: got %s, expected 'valid-refresh-token'",
				session.GetRefreshToken())
		}

		// Check that the access token was updated
		if session.GetAccessToken() != "new-id-token-from-google" {
			t.Errorf("Access token not updated: got %s, expected 'new-id-token-from-google'",
				session.GetAccessToken())
		}
	})
}

// No need to redefine MockTokenExchanger - it's already defined in main_test.go
