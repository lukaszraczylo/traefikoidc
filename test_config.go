package traefikoidc

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// TestConfig manages test execution configuration and performance settings
type TestConfig struct {
	// Test execution modes
	ExtendedTests bool // Run extended/stress tests
	LongTests     bool // Run long-running performance tests
	QuickMode     bool // Quick smoke tests only

	// Performance settings
	MaxConcurrency  int           // Maximum concurrent operations
	MaxIterations   int           // Maximum test iterations
	DefaultTimeout  time.Duration // Default test timeout
	MemoryThreshold float64       // Memory growth threshold in MB
	GoroutineGrowth int           // Acceptable goroutine growth

	// Cache settings for tests
	CacheSize       int           // Default cache size for tests
	CleanupInterval time.Duration // Cleanup interval for tests

	// Environment-specific overrides
	MemoryStressTest bool // Enable memory stress tests
	ConcurrencyTest  bool // Enable high concurrency tests
	LeakDetection    bool // Enable memory leak detection
}

// NewTestConfig creates a test configuration based on flags and environment
func NewTestConfig() *TestConfig {
	config := &TestConfig{
		// Default quick mode settings - very conservative for 30s target
		ExtendedTests:    false,
		LongTests:        false,
		QuickMode:        true,
		MaxConcurrency:   2,                     // Reduced for quick mode
		MaxIterations:    1,                     // Minimal iterations for quick smoke tests
		DefaultTimeout:   5 * time.Second,       // Shorter timeout
		MemoryThreshold:  1.0,                   // Strict memory limit
		GoroutineGrowth:  1,                     // Very strict goroutine limit
		CacheSize:        10,                    // Small cache size
		CleanupInterval:  50 * time.Millisecond, // Faster cleanup
		MemoryStressTest: false,
		ConcurrencyTest:  false,
		LeakDetection:    false, // Disable by default in quick mode for speed
	}

	// Check for extended test flag
	if os.Getenv("RUN_EXTENDED_TESTS") == "1" || os.Getenv("RUN_EXTENDED_TESTS") == "true" {
		config.EnableExtendedTests()
	}

	// Check for long test flag
	if os.Getenv("RUN_LONG_TESTS") == "1" || os.Getenv("RUN_LONG_TESTS") == "true" {
		config.EnableLongTests()
	}

	// Check for stress tests
	if os.Getenv("RUN_STRESS_TESTS") == "1" || os.Getenv("RUN_STRESS_TESTS") == "true" {
		config.EnableStressTests()
	}

	// Check for memory leak detection override
	if os.Getenv("DISABLE_LEAK_DETECTION") == "1" || os.Getenv("DISABLE_LEAK_DETECTION") == "true" {
		config.LeakDetection = false
	}

	// Parse custom concurrency limit
	if concStr := os.Getenv("TEST_MAX_CONCURRENCY"); concStr != "" {
		if conc, err := strconv.Atoi(concStr); err == nil && conc > 0 {
			config.MaxConcurrency = conc
		}
	}

	// Parse custom iteration limit
	if iterStr := os.Getenv("TEST_MAX_ITERATIONS"); iterStr != "" {
		if iter, err := strconv.Atoi(iterStr); err == nil && iter > 0 {
			config.MaxIterations = iter
		}
	}

	// Parse memory threshold
	if memStr := os.Getenv("TEST_MEMORY_THRESHOLD_MB"); memStr != "" {
		if mem, err := strconv.ParseFloat(memStr, 64); err == nil && mem > 0 {
			config.MemoryThreshold = mem
		}
	}

	return config
}

// EnableExtendedTests switches to extended test mode
func (c *TestConfig) EnableExtendedTests() {
	c.ExtendedTests = true
	c.QuickMode = false
	c.MaxConcurrency = 20
	c.MaxIterations = 10
	c.DefaultTimeout = 30 * time.Second
	c.MemoryThreshold = 10.0
	c.GoroutineGrowth = 5
	c.CacheSize = 200
	c.CleanupInterval = 50 * time.Millisecond
	c.ConcurrencyTest = true
}

// EnableLongTests switches to long-running test mode
func (c *TestConfig) EnableLongTests() {
	c.LongTests = true
	c.QuickMode = false
	c.MaxConcurrency = 50
	c.MaxIterations = 100
	c.DefaultTimeout = 60 * time.Second
	c.MemoryThreshold = 50.0
	c.GoroutineGrowth = 10
	c.CacheSize = 1000
	c.CleanupInterval = 10 * time.Millisecond
	c.ConcurrencyTest = true
	c.MemoryStressTest = true
}

// EnableStressTests switches to stress test mode
func (c *TestConfig) EnableStressTests() {
	c.ExtendedTests = true
	c.LongTests = true
	c.QuickMode = false
	c.MaxConcurrency = 100
	c.MaxIterations = 500
	c.DefaultTimeout = 120 * time.Second
	c.MemoryThreshold = 100.0
	c.GoroutineGrowth = 20
	c.CacheSize = 2000
	c.CleanupInterval = 5 * time.Millisecond
	c.ConcurrencyTest = true
	c.MemoryStressTest = true
}

// ShouldSkipTest determines if a test should be skipped based on config
func (c *TestConfig) ShouldSkipTest(t *testing.T, testType TestType) bool {
	// Always respect testing.Short() - skip everything except basic quick tests
	if testing.Short() {
		switch testType {
		case TestTypeQuick:
			return false // Allow quick tests
		case TestTypeExtended, TestTypeLong, TestTypeMemoryStress, TestTypeConcurrencyStress:
			t.Skip("Skipping extended test in short mode")
			return true
		case TestTypeLeakDetection:
			// Skip leak detection in short mode unless explicitly enabled
			if !c.LeakDetection {
				t.Skip("Skipping leak detection test in short mode (use RUN_EXTENDED_TESTS=1 to enable)")
				return true
			}
		}
	}

	// Check specific test type flags
	switch testType {
	case TestTypeExtended:
		if !c.ExtendedTests {
			t.Skip("Skipping extended test (use RUN_EXTENDED_TESTS=1 to enable)")
			return true
		}
	case TestTypeLong:
		if !c.LongTests {
			t.Skip("Skipping long test (use RUN_LONG_TESTS=1 to enable)")
			return true
		}
	case TestTypeMemoryStress:
		if !c.MemoryStressTest {
			t.Skip("Skipping memory stress test (use RUN_STRESS_TESTS=1 to enable)")
			return true
		}
	case TestTypeConcurrencyStress:
		if !c.ConcurrencyTest {
			t.Skip("Skipping concurrency stress test (use RUN_EXTENDED_TESTS=1 to enable)")
			return true
		}
	case TestTypeLeakDetection:
		if !c.LeakDetection {
			t.Skip("Skipping leak detection test (DISABLE_LEAK_DETECTION=1 set)")
			return true
		}
	}

	return false
}

// AdjustMemoryLeakTestCase adjusts a memory leak test case based on configuration
func (c *TestConfig) AdjustMemoryLeakTestCase(testCase *MemoryLeakTestCase) {
	// Adjust iterations
	if testCase.Iterations > c.MaxIterations {
		testCase.Iterations = c.MaxIterations
	}

	// Ensure minimum of 1 iteration
	if testCase.Iterations < 1 {
		testCase.Iterations = 1
	}

	// Adjust memory threshold
	if testCase.MaxMemoryGrowthMB > c.MemoryThreshold && c.QuickMode {
		testCase.MaxMemoryGrowthMB = c.MemoryThreshold
	}

	// Adjust goroutine growth
	if testCase.MaxGoroutineGrowth > c.GoroutineGrowth && c.QuickMode {
		testCase.MaxGoroutineGrowth = c.GoroutineGrowth
	}

	// Adjust timeout
	if testCase.Timeout > c.DefaultTimeout && c.QuickMode {
		testCase.Timeout = c.DefaultTimeout
	} else if testCase.Timeout == 0 {
		testCase.Timeout = c.DefaultTimeout
	}
}

// AdjustConcurrencyParams adjusts concurrency parameters for tests
func (c *TestConfig) AdjustConcurrencyParams(requested int) int {
	if requested > c.MaxConcurrency {
		return c.MaxConcurrency
	}
	return requested
}

// GetCacheSize returns appropriate cache size for tests
func (c *TestConfig) GetCacheSize() int {
	return c.CacheSize
}

// GetCleanupInterval returns appropriate cleanup interval for tests
func (c *TestConfig) GetCleanupInterval() time.Duration {
	return c.CleanupInterval
}

// TestType represents different categories of tests
type TestType int

const (
	TestTypeQuick TestType = iota
	TestTypeExtended
	TestTypeLong
	TestTypeMemoryStress
	TestTypeConcurrencyStress
	TestTypeLeakDetection
)

// String returns string representation of test type
func (tt TestType) String() string {
	switch tt {
	case TestTypeQuick:
		return "quick"
	case TestTypeExtended:
		return "extended"
	case TestTypeLong:
		return "long"
	case TestTypeMemoryStress:
		return "memory-stress"
	case TestTypeConcurrencyStress:
		return "concurrency-stress"
	case TestTypeLeakDetection:
		return "leak-detection"
	default:
		return "unknown"
	}
}

// Global test configuration instance
var globalTestConfig *TestConfig

// GetTestConfig returns the global test configuration
func GetTestConfig() *TestConfig {
	if globalTestConfig == nil {
		globalTestConfig = NewTestConfig()
	}
	return globalTestConfig
}

// SetTestConfig sets the global test configuration (useful for testing)
func SetTestConfig(config *TestConfig) {
	globalTestConfig = config
}
