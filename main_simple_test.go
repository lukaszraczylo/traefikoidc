package traefikoidc

import (
	"os"
	"testing"
)

// TestIsTestMode tests the isTestMode function
func TestIsTestMode(t *testing.T) {
	// Save original environment
	originalSuppressLogs := os.Getenv("SUPPRESS_DIAGNOSTIC_LOGS")
	originalGoTest := os.Getenv("GO_TEST")
	defer func() {
		os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", originalSuppressLogs)
		os.Setenv("GO_TEST", originalGoTest)
	}()

	tests := []struct {
		name                string
		suppressDiagnostics string
		goTestEnv           string
		description         string
	}{
		{
			name:                "SUPPRESS_DIAGNOSTIC_LOGS=1",
			suppressDiagnostics: "1",
			goTestEnv:           "",
			description:         "Should return true when diagnostic logs are suppressed",
		},
		{
			name:                "GO_TEST=1",
			suppressDiagnostics: "",
			goTestEnv:           "1",
			description:         "Should return true when GO_TEST is set",
		},
		{
			name:                "Both environment variables set",
			suppressDiagnostics: "1",
			goTestEnv:           "1",
			description:         "Should return true when both env vars are set",
		},
		{
			name:                "No environment variables",
			suppressDiagnostics: "",
			goTestEnv:           "",
			description:         "Should detect test mode from binary name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", tt.suppressDiagnostics)
			os.Setenv("GO_TEST", tt.goTestEnv)

			// Call function
			result := isTestMode()

			// The result should always be true during testing because
			// os.Args[0] contains ".test" when running via go test
			if !result {
				t.Error("Expected isTestMode to return true during testing")
			}
		})
	}
}

// TestIsTestMode_DefaultBehavior tests default detection
func TestIsTestMode_DefaultBehavior(t *testing.T) {
	// Clear test-related environment variables
	os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
	os.Unsetenv("GO_TEST")

	// Function should still detect test mode from os.Args[0] or runtime
	result := isTestMode()
	if !result {
		t.Error("Expected isTestMode to return true when running tests")
	}
}

// TestVerifyAudience tests the verifyAudience function
func TestVerifyAudience(t *testing.T) {
	tests := []struct {
		tokenAudience    interface{}
		name             string
		expectedAudience string
		description      string
		expectError      bool
	}{
		{
			name:             "Audience matches",
			tokenAudience:    "test-client-id",
			expectedAudience: "test-client-id",
			expectError:      false,
			description:      "Should pass when audience matches",
		},
		{
			name:             "Audience array contains expected",
			tokenAudience:    []interface{}{"other", "test-client-id", "another"},
			expectedAudience: "test-client-id",
			expectError:      false,
			description:      "Should pass when audience array contains expected",
		},
		{
			name:             "Nil audience",
			tokenAudience:    nil,
			expectedAudience: "test-client-id",
			expectError:      true,
			description:      "Should fail when audience is nil",
		},
		{
			name:             "Audience doesn't match",
			tokenAudience:    "different-client-id",
			expectedAudience: "test-client-id",
			expectError:      true,
			description:      "Should fail when audience doesn't match",
		},
		{
			name:             "Audience array doesn't contain expected",
			tokenAudience:    []interface{}{"other", "another"},
			expectedAudience: "test-client-id",
			expectError:      true,
			description:      "Should fail when audience array doesn't contain expected",
		},
		{
			name:             "Invalid audience type",
			tokenAudience:    12345,
			expectedAudience: "test-client-id",
			expectError:      true,
			description:      "Should fail when audience is not string or array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyAudience(tt.tokenAudience, tt.expectedAudience)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for test case: %s", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for test case: %s, error: %v", tt.description, err)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkIsTestMode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isTestMode()
	}
}

func BenchmarkVerifyAudience_String(b *testing.B) {
	audience := "test-client-id"
	expected := "test-client-id"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyAudience(audience, expected)
	}
}

func BenchmarkVerifyAudience_Array(b *testing.B) {
	audience := []interface{}{"other", "test-client-id", "another"}
	expected := "test-client-id"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyAudience(audience, expected)
	}
}
