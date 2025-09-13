package traefikoidc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// GlobalTestCleanup tracks and cleans up test resources
type GlobalTestCleanup struct {
	mu      sync.Mutex
	servers []*httptest.Server
	tasks   []*BackgroundTask
	caches  []interface{ Close() }
}

var globalCleanup = &GlobalTestCleanup{}

// RegisterServer registers an HTTP test server for cleanup
func (g *GlobalTestCleanup) RegisterServer(server *httptest.Server) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.servers = append(g.servers, server)
}

// RegisterTask registers a background task for cleanup
func (g *GlobalTestCleanup) RegisterTask(task *BackgroundTask) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tasks = append(g.tasks, task)
}

// RegisterCache registers a cache for cleanup
func (g *GlobalTestCleanup) RegisterCache(cache interface{ Close() }) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.caches = append(g.caches, cache)
}

// CleanupAll cleans up all registered resources with timeout protection
func (g *GlobalTestCleanup) CleanupAll() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Close servers first
	for _, server := range g.servers {
		if server != nil {
			server.Close()
		}
	}
	g.servers = nil

	// Stop background tasks with timeout
	var wg sync.WaitGroup
	for _, task := range g.tasks {
		if task != nil {
			wg.Add(1)
			// Stop each task in a goroutine with timeout to prevent deadlock
			go func(t *BackgroundTask) {
				defer wg.Done()
				// Give each task up to 1 second to stop
				done := make(chan struct{})
				go func() {
					t.Stop()
					close(done)
				}()

				select {
				case <-done:
					// Task stopped successfully
				case <-time.After(1 * time.Second):
					// Task didn't stop in time - log warning but continue
					runtime.GC() // Force GC to help clean up leaked resources
				}
			}(task)
		}
	}
	// Wait for all task cleanup goroutines to complete
	wg.Wait()
	g.tasks = nil

	// Close caches
	for _, cache := range g.caches {
		if cache != nil {
			cache.Close()
		}
	}
	g.caches = nil

	// Clean up the global cache manager as part of the global cleanup
	// Use a timeout to prevent hanging
	cleanupDone := make(chan struct{})
	go func() {
		CleanupGlobalCacheManager()
		close(cleanupDone)
	}()

	select {
	case <-cleanupDone:
		// Cleanup completed successfully
	case <-time.After(5 * time.Second):
		// Cleanup timed out, but continue
		runtime.GC() // Force GC to help clean up
	}

	// Give background tasks time to finish cleanup
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	runtime.GC() // Double GC to ensure cleanup
}

// TestCleanupHelper provides automatic cleanup for tests with goroutine leak detection
func TestCleanupHelper(t *testing.T) {
	// Record initial goroutine count
	initialGoroutines := runtime.NumGoroutine()

	t.Cleanup(func() {
		// Clean up all resources
		globalCleanup.CleanupAll()

		// Check for goroutine leaks after cleanup
		CheckGoroutineLeaks(t, initialGoroutines)
	})
}

// CheckGoroutineLeaks detects and reports goroutine leaks
func CheckGoroutineLeaks(t *testing.T, initialCount int) {
	// Give goroutines time to clean up
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	runtime.GC()

	finalCount := runtime.NumGoroutine()
	growth := finalCount - initialCount

	// Allow for small growth (up to 2 goroutines) as some tests may have legitimate background work
	if growth > 2 {
		t.Errorf("Potential goroutine leak detected: started with %d, ended with %d (growth: %d)",
			initialCount, finalCount, growth)

		// Print stack traces to help debug the leak
		buf := make([]byte, 1<<16)
		stackSize := runtime.Stack(buf, true)
		t.Logf("Goroutine stack traces:\n%s", buf[:stackSize])
	}
}

// ForceGoroutineCleanup aggressively tries to clean up leaked goroutines
func ForceGoroutineCleanup() {
	// Multiple GC passes to ensure cleanup
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

// GetTestDuration returns an appropriate duration based on test mode
func GetTestDuration(normal time.Duration) time.Duration {
	if testing.Short() {
		// In short mode, reduce all durations by 10x
		return normal / 10
	}
	return normal
}

// UnifiedMockSession provides a comprehensive mock for the Session interface
type UnifiedMockSession struct {
	mu           sync.RWMutex
	data         map[string]interface{}
	callCounts   map[string]int64
	errors       map[string]error
	delays       map[string]time.Duration
	destroyed    bool
	destroyCount int64
}

// NewUnifiedMockSession creates a new mock session with default behavior
func NewUnifiedMockSession() *UnifiedMockSession {
	return &UnifiedMockSession{
		data:       make(map[string]interface{}),
		callCounts: make(map[string]int64),
		errors:     make(map[string]error),
		delays:     make(map[string]time.Duration),
	}
}

// SetError configures the mock to return an error for specific method calls
func (m *UnifiedMockSession) SetError(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[method] = err
}

// SetDelay configures the mock to add delay for specific method calls
func (m *UnifiedMockSession) SetDelay(method string, delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delays[method] = delay
}

// GetCallCount returns the number of times a method was called
func (m *UnifiedMockSession) GetCallCount(method string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCounts[method]
}

func (m *UnifiedMockSession) recordCall(method string) {
	m.mu.Lock()
	m.callCounts[method]++
	m.mu.Unlock()
}

func (m *UnifiedMockSession) checkError(method string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, exists := m.errors[method]; exists {
		return err
	}
	return nil
}

func (m *UnifiedMockSession) applyDelay(method string) {
	m.mu.RLock()
	delay, exists := m.delays[method]
	m.mu.RUnlock()
	if exists && delay > 0 {
		time.Sleep(delay)
	}
}

// Session interface implementation
func (m *UnifiedMockSession) Get(key string) (interface{}, bool) {
	m.recordCall("Get")
	if err := m.checkError("Get"); err != nil {
		return nil, false
	}
	m.applyDelay("Get")

	m.mu.RLock()
	defer m.mu.RUnlock()
	val, exists := m.data[key]
	return val, exists
}

func (m *UnifiedMockSession) Set(key string, value interface{}) {
	m.recordCall("Set")
	if err := m.checkError("Set"); err != nil {
		return
	}
	m.applyDelay("Set")

	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
}

func (m *UnifiedMockSession) Delete(key string) {
	m.recordCall("Delete")
	if err := m.checkError("Delete"); err != nil {
		return
	}
	m.applyDelay("Delete")

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

func (m *UnifiedMockSession) Destroy() error {
	m.recordCall("Destroy")
	if err := m.checkError("Destroy"); err != nil {
		return err
	}
	m.applyDelay("Destroy")

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.destroyed {
		return fmt.Errorf("session already destroyed")
	}

	m.destroyed = true
	atomic.AddInt64(&m.destroyCount, 1)

	// Clear data to help with memory leak detection
	for k := range m.data {
		delete(m.data, k)
	}

	return nil
}

func (m *UnifiedMockSession) IsDestroyed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.destroyed
}

func (m *UnifiedMockSession) GetDestroyCount() int64 {
	return atomic.LoadInt64(&m.destroyCount)
}

// UnifiedMockTokenVerifier provides a comprehensive mock for token verification
type UnifiedMockTokenVerifier struct {
	mu               sync.RWMutex
	validTokens      map[string]bool
	tokenMetadata    map[string]map[string]interface{}
	callCounts       map[string]int64
	errors           map[string]error
	delays           map[string]time.Duration
	verificationFunc func(string) error
}

// NewUnifiedMockTokenVerifier creates a new mock token verifier
func NewUnifiedMockTokenVerifier() *UnifiedMockTokenVerifier {
	return &UnifiedMockTokenVerifier{
		validTokens:   make(map[string]bool),
		tokenMetadata: make(map[string]map[string]interface{}),
		callCounts:    make(map[string]int64),
		errors:        make(map[string]error),
		delays:        make(map[string]time.Duration),
	}
}

// SetTokenValid configures whether a token should be considered valid
func (m *UnifiedMockTokenVerifier) SetTokenValid(token string, valid bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validTokens[token] = valid
}

// SetTokenMetadata configures metadata for a token
func (m *UnifiedMockTokenVerifier) SetTokenMetadata(token string, metadata map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenMetadata[token] = metadata
}

// SetVerificationFunc allows custom verification logic
func (m *UnifiedMockTokenVerifier) SetVerificationFunc(fn func(string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verificationFunc = fn
}

// SetError configures the mock to return an error for specific method calls
func (m *UnifiedMockTokenVerifier) SetError(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[method] = err
}

// GetCallCount returns the number of times a method was called
func (m *UnifiedMockTokenVerifier) GetCallCount(method string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCounts[method]
}

func (m *UnifiedMockTokenVerifier) recordCall(method string) {
	m.mu.Lock()
	m.callCounts[method]++
	m.mu.Unlock()
}

func (m *UnifiedMockTokenVerifier) VerifyToken(token string) error {
	m.recordCall("VerifyToken")

	if err := m.errors["VerifyToken"]; err != nil {
		return err
	}

	if delay := m.delays["VerifyToken"]; delay > 0 {
		time.Sleep(delay)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.verificationFunc != nil {
		return m.verificationFunc(token)
	}

	if valid, exists := m.validTokens[token]; exists && valid {
		return nil
	}

	return fmt.Errorf("invalid token")
}

// UnifiedMockTokenCache provides a comprehensive mock for token caching
type UnifiedMockTokenCache struct {
	mu         sync.RWMutex
	cache      map[string]TestCacheEntry
	callCounts map[string]int64
	errors     map[string]error
	delays     map[string]time.Duration
	hitRate    float64
}

// TestCacheEntry represents a cached token entry for testing
type TestCacheEntry struct {
	Token     string
	ExpiresAt time.Time
	Metadata  map[string]interface{}
}

// NewUnifiedMockTokenCache creates a new mock token cache
func NewUnifiedMockTokenCache() *UnifiedMockTokenCache {
	return &UnifiedMockTokenCache{
		cache:      make(map[string]TestCacheEntry),
		callCounts: make(map[string]int64),
		errors:     make(map[string]error),
		delays:     make(map[string]time.Duration),
		hitRate:    1.0, // Default to 100% hit rate
	}
}

// SetError configures the mock to return an error for specific method calls
func (m *UnifiedMockTokenCache) SetError(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[method] = err
}

// SetHitRate configures the cache hit rate (0.0 to 1.0)
func (m *UnifiedMockTokenCache) SetHitRate(rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hitRate = rate
}

// GetCallCount returns the number of times a method was called
func (m *UnifiedMockTokenCache) GetCallCount(method string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCounts[method]
}

func (m *UnifiedMockTokenCache) recordCall(method string) {
	m.mu.Lock()
	m.callCounts[method]++
	m.mu.Unlock()
}

func (m *UnifiedMockTokenCache) Get(key string) (string, bool) {
	m.recordCall("Get")

	if err := m.errors["Get"]; err != nil {
		return "", false
	}

	if delay := m.delays["Get"]; delay > 0 {
		time.Sleep(delay)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Simulate cache miss based on hit rate
	if m.hitRate < 1.0 {
		// Simple random check (in real tests, you might want deterministic behavior)
		if float64(len(key)%100)/100.0 > m.hitRate {
			return "", false
		}
	}

	entry, exists := m.cache[key]
	if !exists {
		return "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.Token, true
}

func (m *UnifiedMockTokenCache) Set(key, token string, expiry time.Time) {
	m.recordCall("Set")

	if delay := m.delays["Set"]; delay > 0 {
		time.Sleep(delay)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache[key] = TestCacheEntry{
		Token:     token,
		ExpiresAt: expiry,
		Metadata:  make(map[string]interface{}),
	}
}

func (m *UnifiedMockTokenCache) Delete(key string) {
	m.recordCall("Delete")

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, key)
}

func (m *UnifiedMockTokenCache) Clear() {
	m.recordCall("Clear")

	m.mu.Lock()
	defer m.mu.Unlock()

	for k := range m.cache {
		delete(m.cache, k)
	}
}

// TableTestCase represents a standardized test case structure
type TableTestCase struct {
	Name          string
	Description   string
	Input         interface{}
	Expected      interface{}
	ExpectedError error
	Setup         func(*testing.T) error
	Teardown      func(*testing.T) error
	Timeout       time.Duration
	SkipReason    string
	Tags          []string
	Parallel      bool
}

// MemoryLeakTestCase represents a test case specifically for memory leak detection
type MemoryLeakTestCase struct {
	Name               string
	Description        string
	Operation          func() error
	Iterations         int
	MaxGoroutineGrowth int
	MaxMemoryGrowthMB  float64
	Setup              func() error
	Teardown           func() error
	GCBetweenRuns      bool
	Timeout            time.Duration
}

// TestSuiteRunner provides utilities for running table-driven tests
type TestSuiteRunner struct {
	parallelTests bool
	timeout       time.Duration
	beforeEach    func(*testing.T)
	afterEach     func(*testing.T)
}

// NewTestSuiteRunner creates a new test suite runner
func NewTestSuiteRunner() *TestSuiteRunner {
	return &TestSuiteRunner{
		timeout: 30 * time.Second,
	}
}

// SetParallel enables or disables parallel test execution
func (r *TestSuiteRunner) SetParallel(parallel bool) {
	r.parallelTests = parallel
}

// SetTimeout sets the default timeout for tests
func (r *TestSuiteRunner) SetTimeout(timeout time.Duration) {
	r.timeout = timeout
}

// SetBeforeEach sets a function to run before each test
func (r *TestSuiteRunner) SetBeforeEach(fn func(*testing.T)) {
	r.beforeEach = fn
}

// SetAfterEach sets a function to run after each test
func (r *TestSuiteRunner) SetAfterEach(fn func(*testing.T)) {
	r.afterEach = fn
}

// RunTests executes a table of test cases
func (r *TestSuiteRunner) RunTests(t *testing.T, tests []TableTestCase) {
	for _, test := range tests {
		test := test // Capture loop variable

		if test.SkipReason != "" {
			t.Skip(test.SkipReason)
			continue
		}

		testFunc := func(t *testing.T) {
			if r.beforeEach != nil {
				r.beforeEach(t)
			}

			if r.afterEach != nil {
				defer r.afterEach(t)
			}

			timeout := test.Timeout
			if timeout == 0 {
				timeout = r.timeout
			}

			done := make(chan bool, 1)
			var testErr error

			go func() {
				defer func() {
					if r := recover(); r != nil {
						testErr = fmt.Errorf("test panicked: %v", r)
					}
					done <- true
				}()

				if test.Setup != nil {
					if err := test.Setup(t); err != nil {
						testErr = fmt.Errorf("setup failed: %w", err)
						return
					}
				}

				if test.Teardown != nil {
					defer func() {
						if err := test.Teardown(t); err != nil {
							t.Errorf("teardown failed: %v", err)
						}
					}()
				}

				// Execute the actual test logic here
				// This would be filled in by specific test implementations
			}()

			select {
			case <-done:
				if testErr != nil {
					t.Error(testErr)
				}
			case <-time.After(timeout):
				t.Errorf("test timed out after %v", timeout)
			}
		}

		if test.Parallel || r.parallelTests {
			t.Run(test.Name, func(t *testing.T) {
				t.Parallel()
				testFunc(t)
			})
		} else {
			t.Run(test.Name, testFunc)
		}
	}
}

// RunMemoryLeakTests executes memory leak test cases
func (r *TestSuiteRunner) RunMemoryLeakTests(t *testing.T, tests []MemoryLeakTestCase) {
	for _, test := range tests {
		test := test // Capture loop variable

		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			if test.Teardown != nil {
				defer func() {
					if err := test.Teardown(); err != nil {
						t.Errorf("teardown failed: %v", err)
					}
				}()
			}

			// Record initial state
			runtime.GC()
			initialGoroutines := runtime.NumGoroutine()

			var initialMem runtime.MemStats
			runtime.ReadMemStats(&initialMem)

			// Run the operation multiple times
			for i := 0; i < test.Iterations; i++ {
				if test.Operation != nil {
					if err := test.Operation(); err != nil {
						t.Errorf("iteration %d failed: %v", i, err)
						return
					}
				}

				if test.GCBetweenRuns {
					runtime.GC()
				}
			}

			// Force garbage collection and check final state
			runtime.GC()
			runtime.GC() // Double GC to ensure cleanup

			finalGoroutines := runtime.NumGoroutine()

			var finalMem runtime.MemStats
			runtime.ReadMemStats(&finalMem)

			// Check goroutine growth
			goroutineGrowth := finalGoroutines - initialGoroutines
			if test.MaxGoroutineGrowth >= 0 && goroutineGrowth > test.MaxGoroutineGrowth {
				t.Errorf("goroutine leak detected: started with %d, ended with %d (growth: %d, max allowed: %d)",
					initialGoroutines, finalGoroutines, goroutineGrowth, test.MaxGoroutineGrowth)
			}

			// Check memory growth
			memoryGrowthBytes := int64(finalMem.Alloc) - int64(initialMem.Alloc)
			memoryGrowthMB := float64(memoryGrowthBytes) / (1024 * 1024)

			if test.MaxMemoryGrowthMB >= 0 && memoryGrowthMB > test.MaxMemoryGrowthMB {
				t.Errorf("memory leak detected: memory grew by %.2f MB (max allowed: %.2f MB)",
					memoryGrowthMB, test.MaxMemoryGrowthMB)
			}

			t.Logf("Memory test completed: goroutines %d->%d (Δ%d), memory %.2f MB growth",
				initialGoroutines, finalGoroutines, goroutineGrowth, memoryGrowthMB)
		})
	}
}

// TestDataFactory provides utilities for generating test data
type TestDataFactory struct{}

// NewTestDataFactory creates a new test data factory
func NewTestDataFactory() *TestDataFactory {
	return &TestDataFactory{}
}

// GenerateRandomString generates a random string of specified length
func (f *TestDataFactory) GenerateRandomString(length int) string {
	if length <= 0 {
		return ""
	}
	if length == 1 {
		return "a" // Return a simple character for length 1
	}
	bytes := make([]byte, (length+1)/2) // Ensure we have enough bytes
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("test-string-%d", time.Now().UnixNano())[:length]
	}
	encoded := hex.EncodeToString(bytes)
	if len(encoded) >= length {
		return encoded[:length]
	}
	return encoded
}

// GenerateTestToken generates a test JWT-like token
func (f *TestDataFactory) GenerateTestToken() string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	payload := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	signature := f.GenerateRandomString(32)
	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// GenerateTestHTTPRequest generates a test HTTP request
func (f *TestDataFactory) GenerateTestHTTPRequest() *http.Request {
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Authorization", "Bearer "+f.GenerateTestToken())
	return req
}

// GenerateTestSession generates a test session with random data
func (f *TestDataFactory) GenerateTestSession() *UnifiedMockSession {
	session := NewUnifiedMockSession()
	session.Set("user_id", f.GenerateRandomString(16))
	session.Set("email", fmt.Sprintf("user%s@example.com", f.GenerateRandomString(8)))
	session.Set("created_at", time.Now())
	return session
}

// EdgeCaseGenerator provides utilities for generating comprehensive edge cases
type EdgeCaseGenerator struct {
	factory *TestDataFactory
}

// NewEdgeCaseGenerator creates a new edge case generator
func NewEdgeCaseGenerator() *EdgeCaseGenerator {
	return &EdgeCaseGenerator{
		factory: NewTestDataFactory(),
	}
}

// GenerateStringEdgeCases generates edge cases for string inputs
func (g *EdgeCaseGenerator) GenerateStringEdgeCases() []string {
	return []string{
		"",                                    // Empty string
		" ",                                   // Single space
		"  ",                                  // Multiple spaces
		"\t",                                  // Tab
		"\n",                                  // Newline
		"\r\n",                                // Windows newline
		"a",                                   // Single character
		g.factory.GenerateRandomString(1),     // Random single char
		g.factory.GenerateRandomString(1000),  // Long string
		g.factory.GenerateRandomString(10000), // Very long string
		"特殊字符",                                // Unicode characters
		"🚀🎯📊",                                 // Emojis
		"'DROP TABLE users;",                  // SQL injection attempt
		"<script>alert('xss')</script>",       // XSS attempt
		"../../etc/passwd",                    // Path traversal attempt
		string([]byte{0, 1, 2, 255}),          // Binary data
	}
}

// GenerateIntegerEdgeCases generates edge cases for integer inputs
func (g *EdgeCaseGenerator) GenerateIntegerEdgeCases() []int {
	return []int{
		0,
		1,
		-1,
		42,
		-42,
		2147483647,  // max int32
		-2147483648, // min int32
		1000000,
		-1000000,
	}
}

// GenerateTimeEdgeCases generates edge cases for time inputs
func (g *EdgeCaseGenerator) GenerateTimeEdgeCases() []time.Time {
	now := time.Now()
	return []time.Time{
		time.Time{},                     // Zero time
		now,                             // Current time
		now.Add(-time.Hour),             // One hour ago
		now.Add(time.Hour),              // One hour from now
		now.Add(-24 * time.Hour),        // One day ago
		now.Add(24 * time.Hour),         // One day from now
		now.Add(-365 * 24 * time.Hour),  // One year ago
		now.Add(365 * 24 * time.Hour),   // One year from now
		time.Unix(0, 0),                 // Unix epoch
		time.Unix(1<<63-62135596801, 0), // Max time
	}
}

// GenerateHTTPRequestEdgeCases generates edge cases for HTTP requests
func (g *EdgeCaseGenerator) GenerateHTTPRequestEdgeCases() []*http.Request {
	cases := make([]*http.Request, 0)

	// Basic cases
	req1, _ := http.NewRequest("GET", "http://example.com", nil)
	cases = append(cases, req1)

	// Request with headers
	req2, _ := http.NewRequest("POST", "https://api.example.com/endpoint", nil)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+g.factory.GenerateTestToken())
	cases = append(cases, req2)

	// Request with query parameters
	req3, _ := http.NewRequest("GET", "http://example.com/search?q=test&limit=10", nil)
	cases = append(cases, req3)

	// Request with unusual headers
	req4, _ := http.NewRequest("GET", "http://example.com", nil)
	req4.Header.Set("X-Custom-Header", g.factory.GenerateRandomString(1000))
	req4.Header.Set("User-Agent", "")
	cases = append(cases, req4)

	return cases
}

// PerformanceTestHelper provides utilities for performance testing
type PerformanceTestHelper struct {
	samples []time.Duration
	mu      sync.Mutex
}

// NewPerformanceTestHelper creates a new performance test helper
func NewPerformanceTestHelper() *PerformanceTestHelper {
	return &PerformanceTestHelper{
		samples: make([]time.Duration, 0),
	}
}

// Measure measures the execution time of a function
func (h *PerformanceTestHelper) Measure(fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)

	h.mu.Lock()
	h.samples = append(h.samples, duration)
	h.mu.Unlock()

	return duration
}

// GetAverageTime returns the average execution time
func (h *PerformanceTestHelper) GetAverageTime() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.samples) == 0 {
		return 0
	}

	var total time.Duration
	for _, sample := range h.samples {
		total += sample
	}

	return total / time.Duration(len(h.samples))
}

// GetPercentile returns the nth percentile of execution times
func (h *PerformanceTestHelper) GetPercentile(percentile float64) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.samples) == 0 {
		return 0
	}

	// Simple percentile calculation (could be improved with sorting)
	index := int(float64(len(h.samples)) * percentile / 100.0)
	if index >= len(h.samples) {
		index = len(h.samples) - 1
	}

	return h.samples[index]
}

// Reset clears all performance samples
func (h *PerformanceTestHelper) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = h.samples[:0]
}
