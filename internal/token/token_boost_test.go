//go:build !yaegi

package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Helper function to create a simple JWT token for testing
func createTestJWT(header, claims map[string]interface{}) string {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Use fake signature
	return headerB64 + "." + claimsB64 + ".fake-signature"
}

// parseJWT Tests
func TestParseJWT_Valid(t *testing.T) {
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
	claims := map[string]interface{}{"sub": "user123", "aud": "client-id"}
	token := createTestJWT(header, claims)

	jwt, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if jwt == nil {
		t.Fatal("Expected non-nil JWT")
	}

	if jwt.Header["alg"] != "RS256" {
		t.Error("Expected alg to be RS256")
	}

	if jwt.Claims["sub"] != "user123" {
		t.Error("Expected sub to be user123")
	}
}

func TestParseJWT_InvalidFormat(t *testing.T) {
	// Token with wrong number of parts
	_, err := parseJWT("invalid.token")
	if err == nil {
		t.Error("Expected error for invalid token format")
	}

	if !strings.Contains(err.Error(), "expected 3 parts") {
		t.Errorf("Expected error about parts, got: %v", err)
	}
}

func TestParseJWT_InvalidBase64(t *testing.T) {
	// Token with invalid base64
	_, err := parseJWT("!@#$%^.invalid.base64")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

// decodeSegment Tests
func TestDecodeSegment_Valid(t *testing.T) {
	data := map[string]interface{}{
		"field1": "value1",
		"field2": 123,
	}
	jsonData, _ := json.Marshal(data)
	encoded := base64.RawURLEncoding.EncodeToString(jsonData)

	result, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result["field1"] != "value1" {
		t.Error("Expected field1 to be value1")
	}

	if result["field2"].(float64) != 123 {
		t.Error("Expected field2 to be 123")
	}
}

func TestDecodeSegment_WithPadding(t *testing.T) {
	// Create data that needs padding
	data := map[string]interface{}{"test": "value"}
	jsonData, _ := json.Marshal(data)
	// Use standard encoding to get padded version
	encoded := base64.URLEncoding.EncodeToString(jsonData)
	// Remove padding to test the function adds it back
	encoded = strings.TrimRight(encoded, "=")

	result, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("Expected no error with unpadded segment, got: %v", err)
	}

	if result["test"] != "value" {
		t.Error("Expected test to be value")
	}
}

func TestDecodeSegment_InvalidBase64(t *testing.T) {
	_, err := decodeSegment("!@#$%^&*()")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestDecodeSegment_InvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON
	invalid := base64.RawURLEncoding.EncodeToString([]byte("{invalid json"))
	_, err := decodeSegment(invalid)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// DetectTokenType Tests
func TestDetectTokenType_IDToken_StringAudience(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"https://introspect.example.com",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"aud": "test-client", // Matches clientID
		"sub": "user123",
	}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "id_token" {
		t.Errorf("Expected 'id_token', got '%s'", tokenType)
	}
}

func TestDetectTokenType_IDToken_ArrayAudience(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"aud": []interface{}{"test-client", "other-client"},
		"sub": "user123",
	}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "id_token" {
		t.Errorf("Expected 'id_token', got '%s'", tokenType)
	}
}

func TestDetectTokenType_AccessToken_Scope(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"scope": "openid profile email",
		"sub":   "user123",
	}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "access_token" {
		t.Errorf("Expected 'access_token', got '%s'", tokenType)
	}
}

func TestDetectTokenType_IDToken_TokenUse(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"token_use": "id",
		"sub":       "user123",
	}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "id_token" {
		t.Errorf("Expected 'id_token', got '%s'", tokenType)
	}
}

func TestDetectTokenType_AccessToken_TokenUse(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"token_use": "access",
		"sub":       "user123",
	}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "access_token" {
		t.Errorf("Expected 'access_token', got '%s'", tokenType)
	}
}

func TestDetectTokenType_AccessToken_TypHeader(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256", "typ": "at+jwt"}
	claims := map[string]interface{}{"sub": "user123"}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "access_token" {
		t.Errorf("Expected 'access_token', got '%s'", tokenType)
	}
}

func TestDetectTokenType_Unknown(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		nil,
		nil,
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{"sub": "user123"}
	token := createTestJWT(header, claims)

	tokenType, err := introspector.DetectTokenType(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if tokenType != "unknown" {
		t.Errorf("Expected 'unknown', got '%s'", tokenType)
	}
}

// ExtractGroupsAndRoles Tests
func TestExtractGroupsAndRoles_SimpleArrays(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		[]string{"groups"},
		[]string{"roles"},
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []interface{}{"group1", "group2", "group3"},
		"roles":  []interface{}{"role1", "role2"},
	}
	token := createTestJWT(header, claims)

	groups, roles, err := introspector.ExtractGroupsAndRoles(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}

	if len(roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(roles))
	}

	if groups[0] != "group1" {
		t.Errorf("Expected first group to be 'group1', got '%s'", groups[0])
	}
}

func TestExtractGroupsAndRoles_NestedClaims(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		[]string{"resource_access", "account", "roles"},
		[]string{"realm_access", "roles"},
		"",
	)

	header := map[string]interface{}{"alg": "RS256"}
	claims := map[string]interface{}{
		"sub": "user123",
		"resource_access": map[string]interface{}{
			"account": map[string]interface{}{
				"roles": []interface{}{"manage-account", "view-profile"},
			},
		},
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
	}
	token := createTestJWT(header, claims)

	groups, roles, err := introspector.ExtractGroupsAndRoles(token)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(groups))
	}

	if len(roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(roles))
	}
}

func TestExtractGroupsAndRoles_InvalidToken(t *testing.T) {
	introspector := NewIntrospector(
		"test-client",
		"secret",
		"",
		nil,
		&mockLogger{},
		[]string{"groups"},
		[]string{"roles"},
		"",
	)

	_, _, err := introspector.ExtractGroupsAndRoles("invalid.token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

// extractStringSlice Tests (indirect via Introspector)
func TestExtractStringSlice_StringArray(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	val := []interface{}{"value1", "value2", "value3"}
	result := introspector.extractStringSlice(val)

	if len(result) != 3 {
		t.Errorf("Expected 3 values, got %d", len(result))
	}

	if result[0] != "value1" {
		t.Errorf("Expected 'value1', got '%s'", result[0])
	}
}

func TestExtractStringSlice_StringSlice(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	val := []string{"a", "b", "c"}
	result := introspector.extractStringSlice(val)

	if len(result) != 3 {
		t.Errorf("Expected 3 values, got %d", len(result))
	}
}

func TestExtractStringSlice_SingleString(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	result := introspector.extractStringSlice("single-value")

	if len(result) != 1 {
		t.Errorf("Expected 1 value, got %d", len(result))
	}

	if result[0] != "single-value" {
		t.Errorf("Expected 'single-value', got '%s'", result[0])
	}
}

func TestExtractStringSlice_CommaSeparated(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	result := introspector.extractStringSlice("value1,value2,value3")

	if len(result) != 3 {
		t.Errorf("Expected 3 values, got %d", len(result))
	}

	if result[0] != "value1" {
		t.Errorf("Expected 'value1', got '%s'", result[0])
	}
}

func TestExtractStringSlice_EmptyString(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	result := introspector.extractStringSlice("")

	if result != nil {
		t.Errorf("Expected nil for empty string, got %v", result)
	}
}

func TestExtractStringSlice_InvalidType(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	result := introspector.extractStringSlice(12345)

	if result != nil {
		t.Errorf("Expected nil for invalid type, got %v", result)
	}
}

// extractClaimValues Tests (indirect via Introspector)
func TestExtractClaimValues_SimplePath(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	claims := map[string]interface{}{
		"roles": []interface{}{"admin", "user"},
	}

	result := introspector.extractClaimValues(claims, []string{"roles"})

	if len(result) != 2 {
		t.Errorf("Expected 2 values, got %d", len(result))
	}
}

func TestExtractClaimValues_NestedPath(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	claims := map[string]interface{}{
		"resource": map[string]interface{}{
			"account": map[string]interface{}{
				"roles": []interface{}{"role1", "role2"},
			},
		},
	}

	result := introspector.extractClaimValues(claims, []string{"resource", "account", "roles"})

	if len(result) != 2 {
		t.Errorf("Expected 2 values, got %d", len(result))
	}
}

func TestExtractClaimValues_EmptyPath(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	claims := map[string]interface{}{"roles": []interface{}{"admin"}}

	result := introspector.extractClaimValues(claims, []string{})

	if result != nil {
		t.Errorf("Expected nil for empty path, got %v", result)
	}
}

func TestExtractClaimValues_PathNotFound(t *testing.T) {
	introspector := NewIntrospector("", "", "", nil, &mockLogger{}, nil, nil, "")

	claims := map[string]interface{}{"other": "value"}

	result := introspector.extractClaimValues(claims, []string{"roles"})

	if len(result) != 0 {
		t.Errorf("Expected 0 values for missing path, got %d", len(result))
	}
}

// TokenRevocationManager revokeWithProvider test
func TestTokenRevocationManager_RevokeWithProvider(t *testing.T) {
	logger := &mockLogger{}
	cache := newMockCache()
	blacklist := NewTokenBlacklist(cache, logger)
	trm := NewTokenRevocationManager(
		"client-id",
		"client-secret",
		"https://provider.example.com/revoke",
		nil, // http client
		logger,
		blacklist,
	)

	// This function is a simplified placeholder that just logs
	err := trm.revokeWithProvider("test-token", "access_token")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Just verify it doesn't panic - mockLogger doesn't track logs
}
