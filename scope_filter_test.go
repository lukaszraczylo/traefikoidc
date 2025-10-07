package traefikoidc

import (
	"reflect"
	"testing"
)

// mockLogger for testing
type mockScopeFilterLogger struct {
	debugMessages []string
	infoMessages  []string
	errorMessages []string
}

func (l *mockScopeFilterLogger) Debugf(format string, args ...interface{}) {
	l.debugMessages = append(l.debugMessages, format)
}

func (l *mockScopeFilterLogger) Infof(format string, args ...interface{}) {
	l.infoMessages = append(l.infoMessages, format)
}

func (l *mockScopeFilterLogger) Errorf(format string, args ...interface{}) {
	l.errorMessages = append(l.errorMessages, format)
}

// TestNewScopeFilter tests the ScopeFilter constructor
func TestNewScopeFilter(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	if filter == nil {
		t.Fatal("Expected ScopeFilter to be created, got nil")
	}

	// Logger is set correctly (we can't directly compare interface values)
	if filter.logger == nil {
		t.Error("Logger not set in ScopeFilter")
	}
}

// TestFilterSupportedScopes_AllSupported tests when all requested scopes are supported
func TestFilterSupportedScopes_AllSupported(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email"}
	supported := []string{"openid", "profile", "email", "address", "phone"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}

	// Should log debug message that all scopes are supported
	if len(logger.debugMessages) == 0 {
		t.Error("Expected debug messages to be logged")
	}

	// Should not log any info messages (no filtering occurred)
	if len(logger.infoMessages) > 0 {
		t.Error("Expected no info messages when all scopes supported")
	}
}

// TestFilterSupportedScopes_SomeFiltered tests when some scopes need to be filtered
func TestFilterSupportedScopes_SomeFiltered(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email", "offline_access", "custom_scope"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://gitlab.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}

	// Verify offline_access and custom_scope were filtered out
	for _, scope := range result {
		if scope == "offline_access" || scope == "custom_scope" {
			t.Errorf("Scope '%s' should have been filtered out", scope)
		}
	}

	// Should log info message about filtered scopes
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message about filtered scopes")
	}

	// Should log debug messages about supported scopes and final result
	if len(logger.debugMessages) < 2 {
		t.Error("Expected debug messages about provider supported scopes and final result")
	}
}

// TestFilterSupportedScopes_AllFiltered tests when all scopes are filtered (fallback to openid)
func TestFilterSupportedScopes_AllFiltered(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"custom_scope1", "custom_scope2", "unsupported"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected fallback to %v, got %v", expected, result)
	}

	// Should log info message about all scopes being filtered (falling back to openid)
	if len(logger.infoMessages) < 2 { // One for filtered scopes, one for fallback
		t.Error("Expected info messages when all scopes filtered")
	}

	// Should log info message about filtered scopes
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message about filtered scopes")
	}
}

// TestFilterSupportedScopes_NoSupportedScopes tests fallback behavior when no scopes_supported
func TestFilterSupportedScopes_NoSupportedScopes(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email", "offline_access"}
	supported := []string{} // Empty supported list (backward compatibility)
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should return all requested scopes unchanged
	if !reflect.DeepEqual(result, requested) {
		t.Errorf("Expected all requested scopes %v, got %v", requested, result)
	}

	// Should log debug message about no scopes_supported
	if len(logger.debugMessages) == 0 {
		t.Error("Expected debug message about no scopes_supported")
	}

	// Should not log info messages (backward compatibility mode)
	if len(logger.infoMessages) > 0 {
		t.Error("Expected no info messages when no supported scopes provided")
	}
}

// TestFilterSupportedScopes_EmptyRequested tests when requested scopes are empty
func TestFilterSupportedScopes_EmptyRequested(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should return openid as fallback
	expected := []string{"openid"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected fallback to %v when requested empty, got %v", expected, result)
	}

	// Should log info message about empty result (fallback to openid)
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message when no scopes requested")
	}
}

// TestFilterSupportedScopes_DuplicateScopes tests handling of duplicate scope names
func TestFilterSupportedScopes_DuplicateScopes(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "openid", "email"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should preserve duplicates from requested
	expected := []string{"openid", "profile", "openid", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v (preserving duplicates), got %v", expected, result)
	}
}

// TestFilterSupportedScopes_WhitespaceHandling tests trimming of whitespace
func TestFilterSupportedScopes_WhitespaceHandling(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{" openid ", "profile", " email"}
	supported := []string{"openid", "profile", "email", "phone"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should trim whitespace from scopes
	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected trimmed scopes %v, got %v", expected, result)
	}
}

// TestFilterSupportedScopes_EmptyStrings tests filtering out empty strings
func TestFilterSupportedScopes_EmptyStrings(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "", "profile", "  ", "email"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should filter out empty strings
	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v (without empty strings), got %v", expected, result)
	}
}

// TestFilterSupportedScopes_CasePreservation tests that scope case is preserved
func TestFilterSupportedScopes_CasePreservation(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"OpenID", "Profile", "Email"}
	supported := []string{"OpenID", "Profile", "Email"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should preserve case exactly
	expected := []string{"OpenID", "Profile", "Email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected case-preserved %v, got %v", expected, result)
	}
}

// TestFilterSupportedScopes_CaseSensitiveMatching tests case-sensitive matching
func TestFilterSupportedScopes_CaseSensitiveMatching(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "Profile", "EMAIL"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Only "openid" should match (case-sensitive)
	// Profile and EMAIL won't match profile and email in supported list
	expected := []string{"openid"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected case-sensitive filtering %v, got %v", expected, result)
	}

	// Should log info about filtered scopes
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message about filtered scopes due to case mismatch")
	}
}

// TestFilterSupportedScopes_OrderPreservation tests that order is preserved
func TestFilterSupportedScopes_OrderPreservation(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"email", "profile", "openid", "phone"}
	supported := []string{"openid", "profile", "email", "phone", "address"}
	providerURL := "https://auth.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	// Should preserve order from requested
	expected := []string{"email", "profile", "openid", "phone"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected order-preserved %v, got %v", expected, result)
	}
}

// TestFilterSupportedScopes_GitLabScenario simulates GitLab rejecting offline_access
func TestFilterSupportedScopes_GitLabScenario(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	// User requests offline_access but GitLab doesn't support it
	requested := []string{"openid", "profile", "email", "offline_access"}
	supported := []string{"openid", "profile", "email", "read_user", "read_api"}
	providerURL := "https://gitlab.example.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v (without offline_access), got %v", expected, result)
	}

	// Verify offline_access was filtered out
	for _, scope := range result {
		if scope == "offline_access" {
			t.Error("offline_access should have been filtered out for GitLab")
		}
	}

	// Should log info about filtered scopes
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message about offline_access being filtered")
	}
}

// TestFilterSupportedScopes_GoogleScenario simulates Google's scope handling
func TestFilterSupportedScopes_GoogleScenario(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	// Google supports these standard scopes
	requested := []string{"openid", "profile", "email"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://accounts.google.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}

	// No scopes should be filtered
	if len(logger.infoMessages) > 0 {
		t.Error("Expected no filtering for standard Google scopes")
	}
}

// TestFilterSupportedScopes_AzureScenario simulates Azure's scope handling
func TestFilterSupportedScopes_AzureScenario(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	// Azure supports offline_access and OIDC scopes
	requested := []string{"openid", "profile", "email", "offline_access"}
	supported := []string{"openid", "profile", "email", "offline_access"}
	providerURL := "https://login.microsoftonline.com/tenant"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email", "offline_access"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v (including offline_access), got %v", expected, result)
	}

	// All scopes should be retained
	if len(logger.infoMessages) > 0 {
		t.Error("Expected no filtering for standard Azure scopes with offline_access")
	}
}

// TestFilterSupportedScopes_GenericWithFiltering simulates generic provider with filtering
func TestFilterSupportedScopes_GenericWithFiltering(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email", "offline_access", "custom:scope"}
	supported := []string{"openid", "profile", "email", "custom:scope"}
	providerURL := "https://auth.custom-provider.com"

	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email", "custom:scope"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v (without offline_access), got %v", expected, result)
	}

	// offline_access should be filtered
	for _, scope := range result {
		if scope == "offline_access" {
			t.Error("offline_access should have been filtered for this provider")
		}
	}

	// Should log info about filtering
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message about filtered offline_access")
	}
}

// TestFilterSupportedScopes_MultipleProviderURLs tests different provider URLs
func TestFilterSupportedScopes_MultipleProviderURLs(t *testing.T) {
	tests := []struct {
		name        string
		providerURL string
		requested   []string
		supported   []string
		expected    []string
	}{
		{
			name:        "GitLab.com",
			providerURL: "https://gitlab.com",
			requested:   []string{"openid", "offline_access"},
			supported:   []string{"openid"},
			expected:    []string{"openid"},
		},
		{
			name:        "Self-hosted GitLab",
			providerURL: "https://gitlab.example.com",
			requested:   []string{"openid", "profile", "offline_access"},
			supported:   []string{"openid", "profile"},
			expected:    []string{"openid", "profile"},
		},
		{
			name:        "Keycloak",
			providerURL: "https://keycloak.example.com/realms/master",
			requested:   []string{"openid", "profile", "email"},
			supported:   []string{"openid", "profile", "email", "offline_access"},
			expected:    []string{"openid", "profile", "email"},
		},
		{
			name:        "Auth0",
			providerURL: "https://tenant.auth0.com",
			requested:   []string{"openid", "profile", "offline_access"},
			supported:   []string{"openid", "profile", "offline_access"},
			expected:    []string{"openid", "profile", "offline_access"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockScopeFilterLogger{}
			filter := NewScopeFilter(logger)

			result := filter.FilterSupportedScopes(tt.requested, tt.supported, tt.providerURL)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestEnsureOpenIDScope_Present tests when openid is already present
func TestEnsureOpenIDScope_Present(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	scopes := []string{"openid", "profile", "email"}
	result := filter.EnsureOpenIDScope(scopes)

	// Should return scopes unchanged
	if !reflect.DeepEqual(result, scopes) {
		t.Errorf("Expected scopes unchanged %v, got %v", scopes, result)
	}

	// Should not log anything (openid already present)
	if len(logger.debugMessages) > 0 {
		t.Error("Expected no debug messages when openid already present")
	}
}

// TestEnsureOpenIDScope_Missing tests when openid needs to be added
func TestEnsureOpenIDScope_Missing(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	scopes := []string{"profile", "email"}
	result := filter.EnsureOpenIDScope(scopes)

	// Should prepend openid
	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected openid prepended %v, got %v", expected, result)
	}

	// Should log debug message about adding openid
	if len(logger.debugMessages) == 0 {
		t.Error("Expected debug message about adding openid scope")
	}
}

// TestEnsureOpenIDScope_Empty tests with empty scopes list
func TestEnsureOpenIDScope_Empty(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	scopes := []string{}
	result := filter.EnsureOpenIDScope(scopes)

	// Should return just openid
	expected := []string{"openid"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}

	// Should log debug message
	if len(logger.debugMessages) == 0 {
		t.Error("Expected debug message about adding openid scope")
	}
}

// TestEnsureOpenIDScope_Nil tests with nil scopes list
func TestEnsureOpenIDScope_Nil(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	var scopes []string // nil slice
	result := filter.EnsureOpenIDScope(scopes)

	// Should return just openid
	expected := []string{"openid"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// TestEnsureOpenIDScope_CaseVariations tests that case matters for openid detection
func TestEnsureOpenIDScope_CaseVariations(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected []string
	}{
		{
			name:     "Lowercase openid",
			scopes:   []string{"openid", "profile"},
			expected: []string{"openid", "profile"},
		},
		{
			name:     "Mixed case OpenID (should add lowercase)",
			scopes:   []string{"OpenID", "profile"},
			expected: []string{"openid", "OpenID", "profile"},
		},
		{
			name:     "OPENID uppercase (should add lowercase)",
			scopes:   []string{"OPENID", "profile"},
			expected: []string{"openid", "OPENID", "profile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockScopeFilterLogger{}
			filter := NewScopeFilter(logger)

			result := filter.EnsureOpenIDScope(tt.scopes)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestFilterSupportedScopes_IntegrationScenario tests realistic end-to-end scenario
func TestFilterSupportedScopes_IntegrationScenario(t *testing.T) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	// Simulate: User configures plugin with these scopes
	requested := []string{"openid", "profile", "email", "offline_access", "custom_claim"}

	// Provider discovery returns these supported scopes
	supported := []string{"openid", "profile", "email", "read_user"}

	providerURL := "https://gitlab.company.com"

	// Filter should remove offline_access and custom_claim
	result := filter.FilterSupportedScopes(requested, supported, providerURL)

	expected := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}

	// Verify logging occurred
	if len(logger.infoMessages) == 0 {
		t.Error("Expected info message about filtered scopes")
	}

	if len(logger.debugMessages) < 2 {
		t.Error("Expected debug messages about supported scopes and final result")
	}

	// Verify specific scopes were filtered
	for _, scope := range result {
		if scope == "offline_access" || scope == "custom_claim" {
			t.Errorf("Scope '%s' should have been filtered out", scope)
		}
	}
}

// TestFilterSupportedScopes_LoggingBehavior tests comprehensive logging scenarios
func TestFilterSupportedScopes_LoggingBehavior(t *testing.T) {
	tests := []struct {
		name            string
		requested       []string
		supported       []string
		expectDebugOnly bool
		expectInfoLog   bool
	}{
		{
			name:            "All supported - debug only",
			requested:       []string{"openid", "profile"},
			supported:       []string{"openid", "profile", "email"},
			expectDebugOnly: true,
		},
		{
			name:          "Some filtered - info + debug",
			requested:     []string{"openid", "offline_access"},
			supported:     []string{"openid"},
			expectInfoLog: true,
		},
		{
			name:          "All filtered - info + debug",
			requested:     []string{"custom1", "custom2"},
			supported:     []string{"openid"},
			expectInfoLog: true,
		},
		{
			name:            "No supported scopes - debug only",
			requested:       []string{"openid"},
			supported:       []string{},
			expectDebugOnly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockScopeFilterLogger{}
			filter := NewScopeFilter(logger)

			filter.FilterSupportedScopes(tt.requested, tt.supported, "https://example.com")

			hasDebug := len(logger.debugMessages) > 0
			hasInfo := len(logger.infoMessages) > 0

			if tt.expectDebugOnly && (!hasDebug || hasInfo) {
				t.Errorf("Expected only debug logs, got debug=%v info=%v",
					hasDebug, hasInfo)
			}

			if tt.expectInfoLog && !hasInfo {
				t.Error("Expected info log but didn't get one")
			}
		})
	}
}

// Benchmark tests
func BenchmarkFilterSupportedScopes_AllSupported(b *testing.B) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email", "phone"}
	supported := []string{"openid", "profile", "email", "phone", "address"}
	providerURL := "https://example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.FilterSupportedScopes(requested, supported, providerURL)
	}
}

func BenchmarkFilterSupportedScopes_SomeFiltered(b *testing.B) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email", "offline_access", "custom"}
	supported := []string{"openid", "profile", "email"}
	providerURL := "https://example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.FilterSupportedScopes(requested, supported, providerURL)
	}
}

func BenchmarkFilterSupportedScopes_NoSupported(b *testing.B) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	requested := []string{"openid", "profile", "email", "offline_access"}
	supported := []string{}
	providerURL := "https://example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.FilterSupportedScopes(requested, supported, providerURL)
	}
}

func BenchmarkEnsureOpenIDScope_Present(b *testing.B) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	scopes := []string{"openid", "profile", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.EnsureOpenIDScope(scopes)
	}
}

func BenchmarkEnsureOpenIDScope_Missing(b *testing.B) {
	logger := &mockScopeFilterLogger{}
	filter := NewScopeFilter(logger)

	scopes := []string{"profile", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.EnsureOpenIDScope(scopes)
	}
}
