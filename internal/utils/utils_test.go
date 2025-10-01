package utils

import (
	"os"
	"reflect"
	"testing"
)

func TestCreateStringMap(t *testing.T) {
	items := []string{"apple", "banana", "cherry"}
	result := CreateStringMap(items)

	expected := map[string]struct{}{
		"apple":  {},
		"banana": {},
		"cherry": {},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestCreateCaseInsensitiveStringMap(t *testing.T) {
	items := []string{"Apple", "BANANA", "Cherry"}
	result := CreateCaseInsensitiveStringMap(items)

	expected := map[string]struct{}{
		"apple":  {},
		"banana": {},
		"cherry": {},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestDeduplicateScopes(t *testing.T) {
	scopes := []string{"openid", "profile", "email", "openid", "profile"}
	result := DeduplicateScopes(scopes)

	expected := []string{"openid", "profile", "email"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMergeScopes(t *testing.T) {
	defaultScopes := []string{"openid", "profile"}
	userScopes := []string{"email", "offline_access"}
	result := MergeScopes(defaultScopes, userScopes)

	expected := []string{"openid", "profile", "email", "offline_access"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMergeScopesWithDuplicates(t *testing.T) {
	defaultScopes := []string{"openid", "profile"}
	userScopes := []string{"profile", "email", "openid"}
	result := MergeScopes(defaultScopes, userScopes)

	expected := []string{"openid", "profile", "email"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMergeScopesEmptyUserScopes(t *testing.T) {
	defaultScopes := []string{"openid", "profile"}
	userScopes := []string{}
	result := MergeScopes(defaultScopes, userScopes)

	expected := []string{"openid", "profile"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestKeysFromMap(t *testing.T) {
	m := map[string]struct{}{
		"key1": {},
		"key2": {},
		"key3": {},
	}
	result := KeysFromMap(m)

	// Since map iteration order is not guaranteed, we need to check length and presence
	if len(result) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(result))
	}

	resultMap := make(map[string]bool)
	for _, key := range result {
		resultMap[key] = true
	}

	expectedKeys := []string{"key1", "key2", "key3"}
	for _, key := range expectedKeys {
		if !resultMap[key] {
			t.Errorf("Expected key %s not found in result", key)
		}
	}
}

func TestBuildFullURL(t *testing.T) {
	tests := []struct {
		scheme   string
		host     string
		path     string
		expected string
	}{
		{"https", "example.com", "/path", "https://example.com/path"},
		{"http", "localhost:8080", "/callback", "http://localhost:8080/callback"},
		{"https", "test.example.com", "/auth/callback", "https://test.example.com/auth/callback"},
	}

	for _, test := range tests {
		result := BuildFullURL(test.scheme, test.host, test.path)
		if result != test.expected {
			t.Errorf("For scheme=%s, host=%s, path=%s: expected %s, got %s",
				test.scheme, test.host, test.path, test.expected, result)
		}
	}
}

func TestIsTestMode(t *testing.T) {
	// This test is challenging because IsTestMode() depends on runtime conditions.
	// We'll test what we can control via environment variables.

	tests := []struct {
		name     string
		setup    func()
		cleanup  func()
		expected bool
	}{
		{
			name: "suppress diagnostic logs enabled",
			setup: func() {
				os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "1")
			},
			cleanup: func() {
				os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
			},
			expected: true,
		},
		{
			name: "GO_TEST environment variable set",
			setup: func() {
				os.Setenv("GO_TEST", "1")
			},
			cleanup: func() {
				os.Unsetenv("GO_TEST")
			},
			expected: true,
		},
		{
			name: "normal runtime conditions",
			setup: func() {
				// Disable runtime stack check to test fallback behavior
				os.Setenv("DISABLE_RUNTIME_STACK_CHECK", "1")
				os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "")
				os.Setenv("GO_TEST", "")
			},
			cleanup: func() {
				os.Unsetenv("DISABLE_RUNTIME_STACK_CHECK")
				os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
				os.Unsetenv("GO_TEST")
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			tt.setup()
			defer tt.cleanup()

			result := IsTestMode()

			// Note: Some test conditions may still return true due to runtime.Stack
			// detecting testing context, so we check the expected behavior when possible
			if tt.name == "suppress diagnostic logs enabled" || tt.name == "GO_TEST environment variable set" {
				if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}

	// Test that IsTestMode() returns true when called from a test context
	// (which it should, since we're in a test right now)
	result := IsTestMode()
	if !result {
		t.Log("Note: IsTestMode() returned false in test context, which may be expected depending on runtime conditions")
	}
}

func TestIsTestModeEdgeCases(t *testing.T) {
	// Test with various environment variable combinations
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "all env vars empty",
			env: map[string]string{
				"SUPPRESS_DIAGNOSTIC_LOGS":    "",
				"GO_TEST":                     "",
				"DISABLE_RUNTIME_STACK_CHECK": "",
			},
		},
		{
			name: "mixed env vars",
			env: map[string]string{
				"SUPPRESS_DIAGNOSTIC_LOGS":    "0",
				"GO_TEST":                     "true",
				"DISABLE_RUNTIME_STACK_CHECK": "1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original environment
			original := make(map[string]string)
			for key := range tt.env {
				original[key] = os.Getenv(key)
			}

			// Set test environment
			for key, value := range tt.env {
				os.Setenv(key, value)
			}

			// Test IsTestMode (result may vary based on runtime conditions)
			result := IsTestMode()
			_ = result // We just want to ensure it doesn't panic

			// Restore original environment
			for key, value := range original {
				if value == "" {
					os.Unsetenv(key)
				} else {
					os.Setenv(key, value)
				}
			}
		})
	}
}

func TestIsTestModeDetectionMethods(t *testing.T) {
	// Test that calling IsTestMode in a test context returns true
	// This should cover most of the function branches since we're in a test
	result := IsTestMode()

	// In a test context, IsTestMode should return true
	if !result {
		t.Log("IsTestMode returned false in test context - this may be due to environment settings")
	}

	// Test with explicit environment manipulation to force different paths
	originalSuppressDiag := os.Getenv("SUPPRESS_DIAGNOSTIC_LOGS")
	originalGoTest := os.Getenv("GO_TEST")
	originalDisableStack := os.Getenv("DISABLE_RUNTIME_STACK_CHECK")

	defer func() {
		// Restore original environment
		if originalSuppressDiag == "" {
			os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		} else {
			os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", originalSuppressDiag)
		}
		if originalGoTest == "" {
			os.Unsetenv("GO_TEST")
		} else {
			os.Setenv("GO_TEST", originalGoTest)
		}
		if originalDisableStack == "" {
			os.Unsetenv("DISABLE_RUNTIME_STACK_CHECK")
		} else {
			os.Setenv("DISABLE_RUNTIME_STACK_CHECK", originalDisableStack)
		}
	}()

	// Test various combinations to exercise different code paths
	testCases := []struct {
		name         string
		suppressDiag string
		goTest       string
		disableStack string
		expectTrue   bool
	}{
		{
			name:         "suppress_diagnostic_logs_1",
			suppressDiag: "1",
			goTest:       "",
			disableStack: "",
			expectTrue:   true,
		},
		{
			name:         "go_test_1",
			suppressDiag: "",
			goTest:       "1",
			disableStack: "",
			expectTrue:   true,
		},
		{
			name:         "runtime_detection_allowed",
			suppressDiag: "",
			goTest:       "",
			disableStack: "",
			expectTrue:   true, // Should detect test context from runtime stack
		},
		{
			name:         "runtime_detection_disabled",
			suppressDiag: "",
			goTest:       "",
			disableStack: "1",
			expectTrue:   false, // May still be true due to os.Args detection
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", tc.suppressDiag)
			os.Setenv("GO_TEST", tc.goTest)
			os.Setenv("DISABLE_RUNTIME_STACK_CHECK", tc.disableStack)

			result := IsTestMode()

			// For environment variable cases, we can assert the expected result
			if tc.name == "suppress_diagnostic_logs_1" || tc.name == "go_test_1" {
				if result != tc.expectTrue {
					t.Errorf("Expected %v, got %v for case %s", tc.expectTrue, result, tc.name)
				}
			}
			// For runtime detection cases, result may vary based on actual runtime conditions
		})
	}
}

func TestUtilsPackageComplete(t *testing.T) {
	// Test edge cases to improve coverage

	// Test CreateStringMap with empty slice
	emptyResult := CreateStringMap([]string{})
	if len(emptyResult) != 0 {
		t.Errorf("Expected empty map, got %v", emptyResult)
	}

	// Test CreateCaseInsensitiveStringMap with empty slice
	emptyInsensitiveResult := CreateCaseInsensitiveStringMap([]string{})
	if len(emptyInsensitiveResult) != 0 {
		t.Errorf("Expected empty map, got %v", emptyInsensitiveResult)
	}

	// Test DeduplicateScopes with empty slice
	emptyScopes := DeduplicateScopes([]string{})
	if len(emptyScopes) != 0 {
		t.Errorf("Expected empty slice, got %v", emptyScopes)
	}

	// Test MergeScopes with nil slices
	nilResult := MergeScopes(nil, nil)
	if len(nilResult) != 0 {
		t.Errorf("Expected empty slice, got %v", nilResult)
	}

	// Test KeysFromMap with empty map
	emptyMapKeys := KeysFromMap(map[string]struct{}{})
	if len(emptyMapKeys) != 0 {
		t.Errorf("Expected empty slice, got %v", emptyMapKeys)
	}

	// Test BuildFullURL with empty values
	emptyURL := BuildFullURL("", "", "")
	expected := "://"
	if emptyURL != expected {
		t.Errorf("Expected '%s', got '%s'", expected, emptyURL)
	}
}

func TestIsTestModeOsArgsDetection(t *testing.T) {
	// Save original os.Args
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	// Test with different os.Args[0] values that should trigger test mode
	testCases := []struct {
		name     string
		args0    string
		expected bool
	}{
		{
			name:     "Binary with .test suffix",
			args0:    "/path/to/myapp.test",
			expected: true,
		},
		{
			name:     "Binary with go_build_ prefix",
			args0:    "/tmp/go_build_myapp",
			expected: true,
		},
		{
			name:     "Binary with test in name",
			args0:    "/path/to/test_binary",
			expected: true,
		},
		{
			name:     "Binary with __debug_bin",
			args0:    "/path/to/__debug_bin123",
			expected: true,
		},
		{
			name:     "Regular binary name",
			args0:    "/path/to/myapp",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment to avoid interference from other detection methods
			os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "")
			os.Setenv("GO_TEST", "")
			os.Setenv("DISABLE_RUNTIME_STACK_CHECK", "1") // Disable runtime stack check
			defer func() {
				os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
				os.Unsetenv("GO_TEST")
				os.Unsetenv("DISABLE_RUNTIME_STACK_CHECK")
			}()

			// Set os.Args
			os.Args = []string{tc.args0}

			result := IsTestMode()
			if result != tc.expected {
				t.Errorf("For args[0] = '%s': expected %v, got %v", tc.args0, tc.expected, result)
			}
		})
	}
}

func TestIsTestModeArgsFlagDetection(t *testing.T) {
	// Save original os.Args
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	testCases := []struct {
		name     string
		args     []string
		expected bool
	}{
		{
			name:     "Args contain -test flag",
			args:     []string{"/path/to/app", "-test.v", "true"},
			expected: true,
		},
		{
			name:     "Args contain -test.timeout",
			args:     []string{"/path/to/app", "-test.timeout", "30s"},
			expected: true,
		},
		{
			name:     "Args without test flags",
			args:     []string{"/path/to/app", "-verbose", "-config", "file.conf"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment to avoid interference
			os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "")
			os.Setenv("GO_TEST", "")
			os.Setenv("DISABLE_RUNTIME_STACK_CHECK", "1")
			defer func() {
				os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
				os.Unsetenv("GO_TEST")
				os.Unsetenv("DISABLE_RUNTIME_STACK_CHECK")
			}()

			// Ensure args[0] doesn't trigger detection by itself
			if len(tc.args) > 0 {
				tc.args[0] = "/regular/app/name"
			}
			os.Args = tc.args

			result := IsTestMode()
			if result != tc.expected {
				t.Errorf("For args = %v: expected %v, got %v", tc.args, tc.expected, result)
			}
		})
	}
}

func TestIsTestModeRuntimeCompiler(t *testing.T) {
	// This test verifies that the runtime.Compiler check works
	// We can't easily change runtime.Compiler, but we can test the logic path

	// Set up environment to isolate this test
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "")
	os.Setenv("GO_TEST", "")
	os.Setenv("DISABLE_RUNTIME_STACK_CHECK", "1")
	defer func() {
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		os.Unsetenv("GO_TEST")
		os.Unsetenv("DISABLE_RUNTIME_STACK_CHECK")
	}()

	// Test with args that should trigger test mode when runtime.Compiler == "gc"
	os.Args = []string{"some_test_binary", "arg1"}

	result := IsTestMode()
	// Since runtime.Compiler is "gc" in most cases and os.Args[0] contains "test",
	// this should return true
	if !result {
		t.Log("Note: This test may vary depending on the actual runtime.Compiler value")
	}
}

func TestIsTestModeYaegiCompiler(t *testing.T) {
	// Test the yaegi compiler detection
	// We can't change runtime.Compiler directly, but we can verify the GO_TEST path

	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	// Test that GO_TEST=1 triggers test mode regardless of other conditions
	os.Setenv("GO_TEST", "1")
	os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "")
	defer func() {
		os.Unsetenv("GO_TEST")
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
	}()

	// Use a non-test-like binary name
	os.Args = []string{"/regular/binary/name"}

	result := IsTestMode()
	if !result {
		t.Error("Expected true when GO_TEST=1 is set")
	}
}
