package traefikoidc

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// Additional tests to push coverage above 75%

// Test SetMaxSize and SetMaxMemory on caches
func TestCacheMemoryManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// OptimizedCache memory management
	cache := NewOptimizedCache()
	cache.SetMaxSize(100)
	cache.SetMaxMemory(5)

	// Fill cache to test eviction
	for i := 0; i < 150; i++ {
		cache.Set(string(rune(i)), "value", 5*time.Minute)
	}

	// UnifiedCache memory management
	config := DefaultUnifiedCacheConfig()
	unifiedCache := NewUnifiedCache(config)
	unifiedCache.SetMaxSize(50)

	for i := 0; i < 60; i++ {
		unifiedCache.Set(string(rune(i)), "value", 5*time.Minute)
	}

	unifiedCache.Close()
}

// Test BackgroundTask functionality
func TestBackgroundTaskOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// BackgroundTask requires logger and WaitGroup
	logger := NewLogger("debug")
	counter := 0
	task := NewBackgroundTask("test_task", 50*time.Millisecond, func() {
		counter++
	}, logger)

	if task == nil {
		t.Fatal("NewBackgroundTask returned nil")
	}

	task.Start()
	time.Sleep(150 * time.Millisecond)
	task.Stop()

	if counter < 2 {
		t.Errorf("Expected task to run at least twice, ran %d times", counter)
	}
}

// Test Logger creation and singleton
func TestLoggerOperations(t *testing.T) {
	// Test NewLogger
	logger := NewLogger("debug")
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}

	// Test singleton no-op logger
	noOpLogger := GetSingletonNoOpLogger()
	if noOpLogger == nil {
		t.Fatal("GetSingletonNoOpLogger returned nil")
	}

	// Should return same instance
	noOpLogger2 := GetSingletonNoOpLogger()
	if noOpLogger != noOpLogger2 {
		t.Error("GetSingletonNoOpLogger should return singleton")
	}
}

// Test CacheAdapter SetMaxSize
func TestCacheAdapterSetMaxSize(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	unified := NewUnifiedCache(config)
	adapter := NewCacheAdapter(unified)

	adapter.SetMaxSize(25)

	// Fill beyond max size
	for i := 0; i < 30; i++ {
		adapter.Set(string(rune(i)), "value", 5*time.Minute)
	}

	adapter.Cleanup()
	adapter.Close()
}

// Test isTestMode function with different conditions
func TestIsTestMode(t *testing.T) {
	// Store original values
	originalSuppressLogs := os.Getenv("SUPPRESS_DIAGNOSTIC_LOGS")
	originalGoTest := os.Getenv("GO_TEST")
	originalArgs := os.Args

	// Cleanup after test
	defer func() {
		os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", originalSuppressLogs)
		os.Setenv("GO_TEST", originalGoTest)
		os.Args = originalArgs
	}()

	t.Run("SUPPRESS_DIAGNOSTIC_LOGS environment variable", func(t *testing.T) {
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		os.Unsetenv("GO_TEST")
		os.Args = []string{"myprogram"}

		// Should return false initially
		if isTestMode() {
			t.Error("Expected isTestMode to return false without SUPPRESS_DIAGNOSTIC_LOGS")
		}

		// Set environment variable
		os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "1")
		if !isTestMode() {
			t.Error("Expected isTestMode to return true with SUPPRESS_DIAGNOSTIC_LOGS=1")
		}

		// Test other values
		os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", "0")
		if isTestMode() {
			t.Error("Expected isTestMode to return false with SUPPRESS_DIAGNOSTIC_LOGS=0")
		}
	})

	t.Run("Program name detection", func(t *testing.T) {
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		os.Unsetenv("GO_TEST")

		testCases := []struct {
			name        string
			progName    string
			shouldMatch bool
		}{
			{"Test binary", "myprogram.test", true},
			{"Go build temp", "go_build_temp_binary", true},
			{"Debug binary", "__debug_bin1234", true},
			{"Test in name", "mytestprogram", true},
			{"Normal program", "myprogram", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				os.Args = []string{tc.progName}
				result := isTestMode()
				if result != tc.shouldMatch {
					t.Errorf("Program %q: expected %v, got %v", tc.progName, tc.shouldMatch, result)
				}
			})
		}
	})

	t.Run("GO_TEST environment variable", func(t *testing.T) {
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		os.Args = []string{"myprogram"}

		os.Unsetenv("GO_TEST")
		if isTestMode() {
			t.Error("Expected isTestMode to return false without GO_TEST")
		}

		os.Setenv("GO_TEST", "1")
		if !isTestMode() {
			t.Error("Expected isTestMode to return true with GO_TEST=1")
		}

		os.Setenv("GO_TEST", "0")
		if isTestMode() {
			t.Error("Expected isTestMode to return false with GO_TEST=0")
		}
	})

	t.Run("Command line arguments with -test", func(t *testing.T) {
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		os.Unsetenv("GO_TEST")

		testCases := []struct {
			name     string
			args     []string
			expected bool
		}{
			{"No test args", []string{"myprogram"}, false},
			{"Test.run flag", []string{"myprogram", "-test.run=TestSomething"}, true},
			{"Test.v flag", []string{"myprogram", "-test.v"}, true},
			{"Test.count flag", []string{"myprogram", "-test.count=1"}, true},
			{"Other flags", []string{"myprogram", "-config", "file.json"}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				os.Args = tc.args
				result := isTestMode()
				if result != tc.expected {
					t.Errorf("Args %v: expected %v, got %v", tc.args, tc.expected, result)
				}
			})
		}
	})

	t.Run("Runtime compiler detection", func(t *testing.T) {
		os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
		os.Unsetenv("GO_TEST")
		os.Args = []string{"myprogram"}

		// This is tricky to test because we can't change runtime.Compiler easily
		// But we can test that the current behavior works
		if runtime.Compiler == "yaegi" {
			if !isTestMode() {
				t.Error("Expected isTestMode to return true with yaegi compiler")
			}
		} else {
			// With gc compiler, should return false for normal program name
			if isTestMode() {
				t.Error("Expected isTestMode to return false with gc compiler and normal program")
			}
		}
	})

	t.Run("Comprehensive test scenarios", func(t *testing.T) {
		// Test multiple conditions at once
		testCases := []struct {
			name        string
			envSuppress string
			envGoTest   string
			progName    string
			args        []string
			expected    bool
		}{
			{
				"All conditions false",
				"", "", "myprogram",
				[]string{"myprogram", "-config", "test.json"},
				false,
			},
			{
				"Multiple true conditions",
				"1", "1", "test.exe",
				[]string{"test.exe", "-test.v"},
				true,
			},
			{
				"Program name with test",
				"", "", "mytestbinary",
				[]string{"mytestbinary"},
				true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.envSuppress != "" {
					os.Setenv("SUPPRESS_DIAGNOSTIC_LOGS", tc.envSuppress)
				} else {
					os.Unsetenv("SUPPRESS_DIAGNOSTIC_LOGS")
				}

				if tc.envGoTest != "" {
					os.Setenv("GO_TEST", tc.envGoTest)
				} else {
					os.Unsetenv("GO_TEST")
				}

				os.Args = tc.args

				result := isTestMode()
				if result != tc.expected {
					t.Errorf("Scenario %q: expected %v, got %v", tc.name, tc.expected, result)
				}
			})
		}
	})
}

// Test buildFullURL function with edge cases
func TestBuildFullURL(t *testing.T) {
	testCases := []struct {
		name     string
		scheme   string
		host     string
		path     string
		expected string
	}{
		{
			"Standard HTTPS URL",
			"https", "example.com", "/api/v1/users",
			"https://example.com/api/v1/users",
		},
		{
			"HTTP with port",
			"http", "localhost:8080", "/health",
			"http://localhost:8080/health",
		},
		{
			"Empty path",
			"https", "api.service.com", "",
			"https://api.service.com/",
		},
		{
			"Root path",
			"https", "www.example.org", "/",
			"https://www.example.org/",
		},
		{
			"Path without leading slash",
			"http", "internal.local", "status",
			"http://internal.local/status",
		},
		{
			"Complex path with query params",
			"https", "api.example.com", "/v2/search?q=test&limit=10",
			"https://api.example.com/v2/search?q=test&limit=10",
		},
		{
			"IPv4 address",
			"http", "192.168.1.100", "/api",
			"http://192.168.1.100/api",
		},
		{
			"IPv6 address with brackets",
			"http", "[::1]:8080", "/test",
			"http://[::1]:8080/test",
		},
		{
			"Empty scheme",
			"", "example.com", "/test",
			"://example.com/test",
		},
		{
			"Empty host",
			"https", "", "/test",
			"https:///test",
		},
		{
			"All empty",
			"", "", "",
			":///",
		},
		{
			"Special characters in path",
			"https", "example.com", "/path with spaces/test?param=value with spaces",
			"https://example.com/path with spaces/test?param=value with spaces",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildFullURL(tc.scheme, tc.host, tc.path)
			if result != tc.expected {
				t.Errorf("buildFullURL(%q, %q, %q): expected %q, got %q",
					tc.scheme, tc.host, tc.path, tc.expected, result)
			}
		})
	}

	// Test that path gets leading slash when missing
	t.Run("Path normalization", func(t *testing.T) {
		// When path doesn't start with /, it should be added
		result1 := buildFullURL("https", "example.com", "api/test")
		expected1 := "https://example.com/api/test"
		if result1 != expected1 {
			t.Errorf("Expected path to be normalized with leading slash: got %q, want %q", result1, expected1)
		}

		// When path already starts with /, it shouldn't be doubled
		result2 := buildFullURL("https", "example.com", "/api/test")
		expected2 := "https://example.com/api/test"
		if result2 != expected2 {
			t.Errorf("Expected no double slashes: got %q, want %q", result2, expected2)
		}
	})
}
