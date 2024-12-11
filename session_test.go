package traefikoidc

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSessionManager tests the SessionManager functionality
func TestSessionManager(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
			name                string
			authenticated       bool
			email               string
			accessToken         string
			refreshToken        string
			expectedCookieCount int
	}{
			{
					name:                "Short tokens",
					authenticated:       true,
					email:               "test@example.com",
					accessToken:         "shortaccesstoken",
					refreshToken:        "shortrefreshtoken",
					expectedCookieCount: 3, // main, access, refresh
			},
			{
					name:          "Long tokens exceeding 4096 bytes",
					authenticated: true,
					email:         "test@example.com",
					accessToken:   strings.Repeat("x", 5000),
					refreshToken:  strings.Repeat("y", 6000),
					// Recalculate expected cookies based on new maxCookieSize
					expectedCookieCount: calculateExpectedCookieCount(strings.Repeat("x", 5000), strings.Repeat("y", 6000)),
			},
			{
				name: "REALLY long tokens, exceeding 25000 bytes",
				authenticated: true,
				email: "test@example.com",
				accessToken: strings.Repeat("x", 25000),
				refreshToken: strings.Repeat("y", 25000),
				expectedCookieCount: calculateExpectedCookieCount(strings.Repeat("x", 25000), strings.Repeat("y", 25000)),
			},
			{
					name:                "Unauthenticated session",
					authenticated:       false,
					email:               "",
					accessToken:         "",
					refreshToken:        "",
					expectedCookieCount: 3, // main, access, refresh
			},
	}

	for _, tc := range tests {
			tc := tc // Capture range variable
			t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest("GET", "/test", nil)
					rr := httptest.NewRecorder()

					session, err := ts.sessionManager.GetSession(req)
					if err != nil {
							t.Fatalf("Failed to get session: %v", err)
					}

					// Set session values
					session.SetAuthenticated(tc.authenticated)
					session.SetEmail(tc.email)
					session.SetAccessToken(tc.accessToken)
					session.SetRefreshToken(tc.refreshToken)

					// Save session
					if err := session.Save(req, rr); err != nil {
							t.Fatalf("Failed to save session: %v", err)
					}

					// Verify cookies are set
					cookies := rr.Result().Cookies()
					if len(cookies) != tc.expectedCookieCount {
							t.Errorf("Expected %d cookies, got %d", tc.expectedCookieCount, len(cookies))
					}

					// Create a new request with the cookies
					newReq := httptest.NewRequest("GET", "/test", nil)
					for _, cookie := range cookies {
							newReq.AddCookie(cookie)
					}

					// Get the session again and verify values
					newSession, err := ts.sessionManager.GetSession(newReq)
					if err != nil {
							t.Fatalf("Failed to get new session: %v", err)
					}

					if newSession.GetAuthenticated() != tc.authenticated {
							t.Errorf("Authentication status not preserved")
					}
					if email := newSession.GetEmail(); email != tc.email {
							t.Errorf("Expected email %s, got %s", tc.email, email)
					}
					if token := newSession.GetAccessToken(); token != tc.accessToken {
							t.Errorf("Access token not preserved")
					}
					if token := newSession.GetRefreshToken(); token != tc.refreshToken {
							t.Errorf("Refresh token not preserved")
					}
			})
	}
}

func calculateExpectedCookieCount(accessToken, refreshToken string) int {
	count := 3 // main, access, refresh

	// Calculate number of chunks for access token
	accessChunks := len(splitIntoChunks(accessToken, maxCookieSize))
	if accessChunks > 1 {
			count += accessChunks
	}

	// Calculate number of chunks for refresh token
	refreshChunks := len(splitIntoChunks(refreshToken, maxCookieSize))
	if refreshChunks > 1 {
			count += refreshChunks
	}

	return count
}