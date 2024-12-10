package traefikoidc

import (
	"net/http/httptest"
	"testing"
)

func TestSessionManager(t *testing.T) {
	logger := NewLogger("info")
	manager := NewSessionManager("test-secret-key", false, logger)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	session, err := manager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Test setting and getting values
	session.SetAuthenticated(true)
	session.SetEmail("test@example.com")
	session.SetAccessToken("test.access.token")
	session.SetRefreshToken("test.refresh.token")

	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Verify cookies are set
	cookies := rr.Result().Cookies()
	if len(cookies) != 3 {
		t.Errorf("Expected 3 cookies, got %d", len(cookies))
	}

	// Create a new request with the cookies
	newReq := httptest.NewRequest("GET", "/test", nil)
	for _, cookie := range cookies {
		newReq.AddCookie(cookie)
	}

	// Get the session again and verify values
	newSession, err := manager.GetSession(newReq)
	if err != nil {
		t.Fatalf("Failed to get new session: %v", err)
	}

	if !newSession.GetAuthenticated() {
		t.Error("Authentication status not preserved")
	}
	if email := newSession.GetEmail(); email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", email)
	}
	if token := newSession.GetAccessToken(); token != "test.access.token" {
		t.Errorf("Expected access token test.access.token, got %s", token)
	}
	if token := newSession.GetRefreshToken(); token != "test.refresh.token" {
		t.Errorf("Expected refresh token test.refresh.token, got %s", token)
	}
}
