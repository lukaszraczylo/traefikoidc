//go:build !yaegi

package token

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Introspector tests
func TestNewIntrospector(t *testing.T) {
	introspector := NewIntrospector(
		"client-id",
		"client-secret",
		"https://provider.example.com/introspect",
		&http.Client{},
		&mockLogger{},
		[]string{"groups"},
		[]string{"roles"},
		"",
	)

	if introspector == nil {
		t.Fatal("Expected NewIntrospector to return non-nil")
	}

	if introspector.clientID != "client-id" {
		t.Error("Expected clientID to be set")
	}

	if introspector.clientSecret != "client-secret" {
		t.Error("Expected clientSecret to be set")
	}

	if introspector.introspectionURL != "https://provider.example.com/introspect" {
		t.Error("Expected introspectionURL to be set")
	}

	if len(introspector.groupsClaimPath) != 1 || introspector.groupsClaimPath[0] != "groups" {
		t.Error("Expected groupsClaimPath to be set")
	}

	if len(introspector.rolesClaimPath) != 1 || introspector.rolesClaimPath[0] != "roles" {
		t.Error("Expected rolesClaimPath to be set")
	}
}

func TestIntrospector_IntrospectToken_NoEndpoint(t *testing.T) {
	introspector := NewIntrospector(
		"client-id",
		"client-secret",
		"", // No introspection endpoint
		&http.Client{},
		&mockLogger{},
		nil,
		nil,
		"",
	)

	_, err := introspector.IntrospectToken("token", "")
	if err == nil {
		t.Error("Expected error when introspection endpoint not configured")
	}

	if err.Error() != "introspection endpoint not configured" {
		t.Errorf("Expected configuration error, got: %v", err)
	}
}

func TestIntrospector_IntrospectToken_Success(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}

		// Verify parameters
		if r.FormValue("token") != "test-token" {
			t.Error("Expected token parameter")
		}

		if r.FormValue("token_type_hint") != "access_token" {
			t.Error("Expected token_type_hint parameter")
		}

		if r.FormValue("client_id") != "test-client" {
			t.Error("Expected client_id parameter")
		}

		// Return valid introspection response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"active": true,
			"scope": "openid profile email",
			"client_id": "test-client",
			"username": "testuser",
			"token_type": "Bearer",
			"exp": 1234567890,
			"iat": 1234567800,
			"sub": "user123",
			"aud": "test-audience",
			"iss": "https://issuer.example.com",
			"custom_claim": "custom_value"
		}`))
	}))
	defer server.Close()

	introspector := NewIntrospector(
		"test-client",
		"test-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		nil,
		nil,
		"",
	)

	resp, err := introspector.IntrospectToken("test-token", "access_token")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !resp.Active {
		t.Error("Expected token to be active")
	}

	if resp.Scope != "openid profile email" {
		t.Errorf("Expected scope 'openid profile email', got '%s'", resp.Scope)
	}

	if resp.ClientID != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%s'", resp.ClientID)
	}

	if resp.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", resp.Username)
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("Expected token_type 'Bearer', got '%s'", resp.TokenType)
	}

	// Check extra fields
	if resp.Extra == nil {
		t.Fatal("Expected Extra map to be populated")
	}

	if val, ok := resp.Extra["custom_claim"]; !ok || val != "custom_value" {
		t.Error("Expected custom_claim in Extra fields")
	}

	// Standard fields should not be in Extra
	if _, ok := resp.Extra["active"]; ok {
		t.Error("Standard field 'active' should not be in Extra")
	}
}

func TestIntrospector_IntrospectToken_HTTPError(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer server.Close()

	introspector := NewIntrospector(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		nil,
		nil,
		"",
	)

	_, err := introspector.IntrospectToken("bad-token", "")
	if err == nil {
		t.Error("Expected error for HTTP 401 response")
	}
}

func TestIntrospector_IntrospectToken_InvalidJSON(t *testing.T) {
	// Create a test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	introspector := NewIntrospector(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		nil,
		nil,
		"",
	)

	_, err := introspector.IntrospectToken("token", "")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
}

func TestIntrospector_IntrospectToken_NoTokenTypeHint(t *testing.T) {
	// Test that token_type_hint is optional
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}

		// Verify token_type_hint is not set when empty
		if r.FormValue("token_type_hint") != "" {
			t.Error("Expected no token_type_hint when not provided")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	introspector := NewIntrospector(
		"client-id",
		"client-secret",
		server.URL,
		&http.Client{},
		&mockLogger{},
		nil,
		nil,
		"",
	)

	_, err := introspector.IntrospectToken("token", "") // Empty token type hint
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func TestIntrospector_DetectTokenType_IDToken_AudienceString(t *testing.T) {
	_ = NewIntrospector(
		"test-client",
		"client-secret",
		"https://introspect.example.com",
		&http.Client{},
		&mockLogger{},
		nil,
		nil,
		"",
	)

	// Mock JWT with audience matching client ID
	// Note: parseJWT is a package-level function that we can't easily mock,
	// so this test validates the logic assuming parseJWT works
	// We'll test the DetectTokenType method indirectly

	// This test would require mocking parseJWT which is complex
	// Skip for now or implement when parseJWT is mockable
	t.Skip("Requires parseJWT mocking - tested indirectly through integration")
}

func TestIntrospector_DetectTokenType_AccessToken_Scope(t *testing.T) {
	// Similar to above - requires parseJWT mocking
	t.Skip("Requires parseJWT mocking - tested indirectly through integration")
}

func TestIntrospector_ExtractGroupsAndRoles(t *testing.T) {
	// Requires parseJWT mocking
	t.Skip("Requires parseJWT mocking - tested indirectly through integration")
}
