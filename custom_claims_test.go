//go:build !yaegi

package traefikoidc

import (
	"testing"
)

// TestCustomClaimNames_DefaultBehavior tests backward compatibility with default claim names
func TestCustomClaimNames_DefaultBehavior(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Explicitly set defaults to test backward compatibility
	ts.tOidc.roleClaimName = "roles"
	ts.tOidc.groupClaimName = "groups"

	// Test that when no custom claim names are configured, it uses defaults "roles" and "groups"
	claims := map[string]interface{}{
		"groups": []interface{}{"admin", "users"},
		"roles":  []interface{}{"editor", "viewer"},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !stringSliceEqual(groups, []string{"admin", "users"}) {
		t.Errorf("Expected groups [admin users], got %v", groups)
	}

	if !stringSliceEqual(roles, []string{"editor", "viewer"}) {
		t.Errorf("Expected roles [editor viewer], got %v", roles)
	}
}

// TestCustomClaimNames_Auth0Namespaced tests Auth0-style namespaced claims
func TestCustomClaimNames_Auth0Namespaced(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names for Auth0
	ts.tOidc.roleClaimName = "https://myapp.com/roles"
	ts.tOidc.groupClaimName = "https://myapp.com/groups"

	// Create token with Auth0-style namespaced claims
	claims := map[string]interface{}{
		"https://myapp.com/groups": []interface{}{"admin", "users"},
		"https://myapp.com/roles":  []interface{}{"editor", "viewer"},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !stringSliceEqual(groups, []string{"admin", "users"}) {
		t.Errorf("Expected groups [admin users], got %v", groups)
	}

	if !stringSliceEqual(roles, []string{"editor", "viewer"}) {
		t.Errorf("Expected roles [editor viewer], got %v", roles)
	}
}

// TestCustomClaimNames_CustomSimpleNames tests custom simple claim names
func TestCustomClaimNames_CustomSimpleNames(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom simple claim names
	ts.tOidc.roleClaimName = "user_roles"
	ts.tOidc.groupClaimName = "user_groups"

	// Create token with custom claim names
	claims := map[string]interface{}{
		"user_groups": []interface{}{"engineering", "product"},
		"user_roles":  []interface{}{"developer", "manager"},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !stringSliceEqual(groups, []string{"engineering", "product"}) {
		t.Errorf("Expected groups [engineering product], got %v", groups)
	}

	if !stringSliceEqual(roles, []string{"developer", "manager"}) {
		t.Errorf("Expected roles [developer manager], got %v", roles)
	}
}

// TestCustomClaimNames_MissingClaims tests behavior when custom claims are missing
func TestCustomClaimNames_MissingClaims(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names
	ts.tOidc.roleClaimName = "custom_roles"
	ts.tOidc.groupClaimName = "custom_groups"

	// Create token WITHOUT the custom claims
	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should return empty slices, not error
	if len(groups) != 0 {
		t.Errorf("Expected empty groups, got %v", groups)
	}

	if len(roles) != 0 {
		t.Errorf("Expected empty roles, got %v", roles)
	}
}

// TestCustomClaimNames_MalformedClaims tests error handling for malformed claims
func TestCustomClaimNames_MalformedRoleClaim(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names
	ts.tOidc.roleClaimName = "custom_roles"

	// Create token with malformed role claim (not an array)
	claims := map[string]interface{}{
		"custom_roles": "this-should-be-an-array",
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	_, _, err = ts.tOidc.extractGroupsAndRoles(token)
	if err == nil {
		t.Error("Expected error for malformed role claim, got nil")
	}

	// Check error message contains the custom claim name
	expectedError := "custom_roles claim is not an array"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestCustomClaimNames_MalformedGroupClaim tests error handling for malformed group claims
func TestCustomClaimNames_MalformedGroupClaim(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names
	ts.tOidc.groupClaimName = "custom_groups"

	// Create token with malformed group claim (not an array)
	claims := map[string]interface{}{
		"custom_groups": 12345, // Not an array
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	_, _, err = ts.tOidc.extractGroupsAndRoles(token)
	if err == nil {
		t.Error("Expected error for malformed group claim, got nil")
	}

	// Check error message contains the custom claim name
	expectedError := "custom_groups claim is not an array"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestCustomClaimNames_PartialConfiguration tests when only one claim name is customized
func TestCustomClaimNames_OnlyRoleCustomized(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure only role claim name (group uses default)
	ts.tOidc.roleClaimName = "https://myapp.com/roles"
	ts.tOidc.groupClaimName = "groups" // default

	// Create token with mixed claim names
	claims := map[string]interface{}{
		"groups":                  []interface{}{"admin"},
		"https://myapp.com/roles": []interface{}{"editor"},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !stringSliceEqual(groups, []string{"admin"}) {
		t.Errorf("Expected groups [admin], got %v", groups)
	}

	if !stringSliceEqual(roles, []string{"editor"}) {
		t.Errorf("Expected roles [editor], got %v", roles)
	}
}

// TestCustomClaimNames_OnlyGroupCustomized tests when only group claim name is customized
func TestCustomClaimNames_OnlyGroupCustomized(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure only group claim name (role uses default)
	ts.tOidc.roleClaimName = "roles" // default
	ts.tOidc.groupClaimName = "https://myapp.com/groups"

	// Create token with mixed claim names
	claims := map[string]interface{}{
		"roles":                    []interface{}{"viewer"},
		"https://myapp.com/groups": []interface{}{"users"},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !stringSliceEqual(groups, []string{"users"}) {
		t.Errorf("Expected groups [users], got %v", groups)
	}

	if !stringSliceEqual(roles, []string{"viewer"}) {
		t.Errorf("Expected roles [viewer], got %v", roles)
	}
}

// TestCustomClaimNames_EmptyArrays tests extraction with empty claim arrays
func TestCustomClaimNames_EmptyArrays(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names
	ts.tOidc.roleClaimName = "https://myapp.com/roles"
	ts.tOidc.groupClaimName = "https://myapp.com/groups"

	// Create token with empty arrays
	claims := map[string]interface{}{
		"https://myapp.com/groups": []interface{}{},
		"https://myapp.com/roles":  []interface{}{},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(groups) != 0 {
		t.Errorf("Expected empty groups, got %v", groups)
	}

	if len(roles) != 0 {
		t.Errorf("Expected empty roles, got %v", roles)
	}
}

// TestCustomClaimNames_NonStringElements tests handling of non-string elements in claim arrays
func TestCustomClaimNames_NonStringInRoleArray(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names
	ts.tOidc.roleClaimName = "custom_roles"

	// Create token with mixed-type array (should skip non-string elements)
	claims := map[string]interface{}{
		"custom_roles": []interface{}{"role1", 12345, "role2", true},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	_, roles, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should only extract string elements
	if !stringSliceEqual(roles, []string{"role1", "role2"}) {
		t.Errorf("Expected roles [role1 role2], got %v", roles)
	}
}

// TestCustomClaimNames_NonStringInGroupArray tests handling of non-string elements in group arrays
func TestCustomClaimNames_NonStringInGroupArray(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure custom claim names
	ts.tOidc.groupClaimName = "custom_groups"

	// Create token with mixed-type array (should skip non-string elements)
	claims := map[string]interface{}{
		"custom_groups": []interface{}{"group1", nil, "group2", 3.14},
	}

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	groups, _, err := ts.tOidc.extractGroupsAndRoles(token)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should only extract string elements
	if !stringSliceEqual(groups, []string{"group1", "group2"}) {
		t.Errorf("Expected groups [group1 group2], got %v", groups)
	}
}
