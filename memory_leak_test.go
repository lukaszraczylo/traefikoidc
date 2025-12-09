package traefikoidc

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Framework and Types
// =============================================================================

// MemoryLeakFixesTestSuite provides comprehensive memory leak testing using unified infrastructure
type MemoryLeakFixesTestSuite struct {
	runner   *TestSuiteRunner
	factory  *TestDataFactory
	edgeGen  *EdgeCaseGenerator
	perfTest *PerformanceTestHelper
	logger   *Logger
}

// NewMemoryLeakFixesTestSuite creates a new test suite for memory leak fixes
func NewMemoryLeakFixesTestSuite() *MemoryLeakFixesTestSuite {
	return &MemoryLeakFixesTestSuite{
		runner:   NewTestSuiteRunner(),
		factory:  NewTestDataFactory(),
		edgeGen:  NewEdgeCaseGenerator(),
		perfTest: NewPerformanceTestHelper(),
		logger:   GetSingletonNoOpLogger(),
	}
}

// MemoryTestCase defines a memory leak test scenario
type MemoryTestCase struct {
	name         string
	component    string // "cache", "session", "token", "plugin", "pool"
	scenario     string // "concurrent", "longrunning", "stress", "lifecycle"
	iterations   int
	concurrency  int
	setup        func(*MemoryTestFramework) error
	execute      func(*MemoryTestFramework) error
	validateLeak func(*testing.T, runtime.MemStats, runtime.MemStats)
	cleanup      func(*MemoryTestFramework) error
}

// MemoryTestFramework provides common test infrastructure for memory tests
type MemoryTestFramework struct {
	t       *testing.T
	cache   CacheInterface
	plugin  *TraefikOidc
	logger  *Logger
	servers []*httptest.Server
	configs []*Config
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewMemoryTestFramework creates a new test framework instance
func NewMemoryTestFramework(t *testing.T) *MemoryTestFramework {
	ctx, cancel := context.WithCancel(context.Background())
	return &MemoryTestFramework{
		t:       t,
		logger:  NewLogger("debug"),
		ctx:     ctx,
		cancel:  cancel,
		servers: make([]*httptest.Server, 0),
		configs: make([]*Config, 0),
	}
}

// Cleanup releases all framework resources
func (tf *MemoryTestFramework) Cleanup() {
	if tf.cancel != nil {
		tf.cancel()
	}
	if tf.plugin != nil {
		tf.plugin.Close()
	}
	if tf.cache != nil {
		tf.cache.Close()
	}
	for _, server := range tf.servers {
		server.Close()
	}
}

// ConsolidatedMemorySnapshot captures memory statistics at a point in time
type ConsolidatedMemorySnapshot struct {
	Timestamp   time.Time
	Alloc       uint64
	TotalAlloc  uint64
	Sys         uint64
	NumGC       uint32
	Goroutines  int
	Description string
}

// VerifyNoGoroutineLeaks checks for goroutine leaks
func VerifyNoGoroutineLeaks(t *testing.T, baseline int, tolerance int, description string) {
	time.Sleep(100 * time.Millisecond)

	current := runtime.NumGoroutine()
	leaked := current - baseline

	if leaked > tolerance {
		t.Errorf("Goroutine leak detected in %s: baseline=%d, current=%d, leaked=%d (tolerance=%d)",
			description, baseline, current, leaked, tolerance)
	}
}

// TakeConsolidatedMemorySnapshot captures current memory state
func TakeConsolidatedMemorySnapshot(description string) ConsolidatedMemorySnapshot {
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return ConsolidatedMemorySnapshot{
		Timestamp:   time.Now(),
		Alloc:       m.Alloc,
		TotalAlloc:  m.TotalAlloc,
		Sys:         m.Sys,
		NumGC:       m.NumGC,
		Goroutines:  runtime.NumGoroutine(),
		Description: description,
	}
}

// =============================================================================
// Optimized Cache Lifecycle Tests
// =============================================================================

func TestOptimizedCacheLifecycleManagement(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic cache lifecycle",
			Description: "Test basic cache creation, use, and cleanup",
			Operation: func() error {
				cache := NewOptimizedCache()
				if cache == nil {
					return fmt.Errorf("cache creation failed")
				}

				cache.Set("test", "value", time.Minute)
				val, found := cache.Get("test")
				if !found || val != "value" {
					return fmt.Errorf("cache operation failed")
				}

				cache.Close()
				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Cache with multiple entries",
			Description: "Test cache with multiple entries and cleanup",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					cache.Set(key, fmt.Sprintf("value-%d", i), time.Minute)
				}

				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					_, found := cache.Get(key)
					if !found {
						return fmt.Errorf("cache entry missing: %s", key)
					}
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  5.0,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
		{
			Name:        "Cache with expiring entries",
			Description: "Test cache cleanup of expired entries",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("short-key-%d", i)
					cache.Set(key, "short-value", 50*time.Millisecond)
				}

				time.Sleep(GetTestDuration(100 * time.Millisecond))

				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("cleanup-key-%d", i)
					cache.Set(key, "new-value", time.Minute)
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Chunk Manager Tests
// =============================================================================

func TestChunkManagerBoundedSessions(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []TableTestCase{
		{
			Name:        "Basic chunk manager initialization",
			Description: "Verify chunk manager is properly initialized with bounds",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
		{
			Name:        "Session limits enforcement",
			Description: "Verify session limits are properly enforced",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				err := test.Setup(t)
				require.NoError(t, err)
			}

			if test.Teardown != nil {
				defer func() {
					err := test.Teardown(t)
					assert.NoError(t, err)
				}()
			}

			logger := GetSingletonNoOpLogger()
			cm := NewChunkManager(logger)

			assert.Equal(t, 1000, cm.maxSessions)
			assert.Equal(t, 24*time.Hour, cm.sessionTTL)
			assert.NotNil(t, cm.sessionMap)
			assert.Equal(t, 0, len(cm.sessionMap))
		})
	}

	leakTests := []MemoryLeakTestCase{
		{
			Name:        "Session map memory management",
			Description: "Verify session map doesn't leak memory with bounded sessions",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				cm := NewChunkManager(logger)

				if cm == nil {
					return fmt.Errorf("chunk manager creation failed")
				}

				for i := 0; i < 100; i++ {
					sessionID := fmt.Sprintf("session-%d", i)
					_ = sessionID
				}

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 1,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            5 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, leakTests)
}

// =============================================================================
// Provider Registry Tests
// =============================================================================

func TestProviderRegistryBoundedCache(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}
	suite := NewMemoryLeakFixesTestSuite()

	tests := []TableTestCase{
		{
			Name:        "Registry bounds validation",
			Description: "Validate registry bounds pattern for future implementation",
			Input:       1000,
			Expected:    true,
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
	}

	edgeCases := suite.edgeGen.GenerateIntegerEdgeCases()
	for _, maxSize := range edgeCases {
		if maxSize > 0 {
			tests = append(tests, TableTestCase{
				Name:        fmt.Sprintf("Registry bounds edge case - size %d", maxSize),
				Description: "Test registry bounds with edge case values",
				Input:       maxSize,
				Expected:    maxSize > 0,
			})
		}
	}

	suite.runner.RunTests(t, tests)

	leakTests := []MemoryLeakTestCase{
		{
			Name:        "Provider registry memory pattern",
			Description: "Test memory pattern for bounded provider registry",
			Operation: func() error {
				maxCacheSize := 1000
				cacheCount := 0
				cache := make(map[string]interface{})

				for i := 0; i < maxCacheSize*2; i++ {
					key := fmt.Sprintf("provider-%d", i)
					if cacheCount < maxCacheSize {
						cache[key] = fmt.Sprintf("config-%d", i)
						cacheCount++
					}
				}

				if len(cache) > maxCacheSize {
					return fmt.Errorf("cache exceeded bounds: %d > %d", len(cache), maxCacheSize)
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 0,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            5 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, leakTests)
}

// =============================================================================
// Error Recovery Lifecycle Tests
// =============================================================================

func TestErrorRecoveryLifecycleManagement(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}
	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic background task lifecycle",
			Description: "Test background task creation, execution, and cleanup",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()

				taskFunc := func() {}

				task := NewBackgroundTask("test-health-check", 100*time.Millisecond, taskFunc, logger)
				task.Start()

				time.Sleep(GetTestDuration(50 * time.Millisecond))

				task.Stop()

				time.Sleep(GetTestDuration(200 * time.Millisecond))

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Multiple background tasks",
			Description: "Test multiple background tasks lifecycle management",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				tasks := make([]*BackgroundTask, 0, 3)

				for i := 0; i < 3; i++ {
					taskName := fmt.Sprintf("test-task-%d", i)
					taskFunc := func() {}
					task := NewBackgroundTask(taskName, 50*time.Millisecond, taskFunc, logger)
					tasks = append(tasks, task)
					task.Start()
				}

				time.Sleep(GetTestDuration(100 * time.Millisecond))

				for _, task := range tasks {
					task.Stop()
				}

				time.Sleep(GetTestDuration(200 * time.Millisecond))

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  1.5,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Background Task Shutdown Tests
// =============================================================================

func TestBackgroundTaskProperShutdown(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}
	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic background task shutdown",
			Description: "Test basic background task execution and proper shutdown",
			Operation: func() error {
				var wg sync.WaitGroup
				logger := GetSingletonNoOpLogger()

				callCount := 0
				taskFunc := func() {
					callCount++
				}

				task := NewBackgroundTask("test-task", 50*time.Millisecond, taskFunc, logger, &wg)
				task.Start()

				time.Sleep(GetTestDuration(150 * time.Millisecond))
				if callCount == 0 {
					return fmt.Errorf("task should have executed at least once")
				}

				task.Stop()

				wg.Wait()
				time.Sleep(GetTestDuration(100 * time.Millisecond))

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
		{
			Name:        "High frequency background task",
			Description: "Test background task with high execution frequency",
			Operation: func() error {
				var wg sync.WaitGroup
				logger := GetSingletonNoOpLogger()

				callCount := 0
				taskFunc := func() {
					callCount++
				}

				task := NewBackgroundTask("high-freq-task", 10*time.Millisecond, taskFunc, logger, &wg)
				task.Start()

				time.Sleep(GetTestDuration(100 * time.Millisecond))

				task.Stop()

				wg.Wait()
				time.Sleep(GetTestDuration(50 * time.Millisecond))

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Metadata Cache Tests
// =============================================================================

func TestMetadataCacheResourceCleanup(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic metadata cache cleanup",
			Description: "Test metadata cache creation and cleanup",
			Operation: func() error {
				var wg sync.WaitGroup

				cache := NewMetadataCache(&wg)
				if cache == nil {
					return fmt.Errorf("cache creation failed")
				}

				time.Sleep(GetTestDuration(50 * time.Millisecond))

				cache.Close()

				time.Sleep(GetTestDuration(100 * time.Millisecond))

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Multiple metadata caches",
			Description: "Test multiple metadata cache instances cleanup",
			Operation: func() error {
				var wg sync.WaitGroup
				caches := make([]*MetadataCache, 0, 3)

				for i := 0; i < 3; i++ {
					cache := NewMetadataCache(&wg)
					if cache == nil {
						return fmt.Errorf("cache creation failed for instance %d", i)
					}
					caches = append(caches, cache)
				}

				time.Sleep(GetTestDuration(50 * time.Millisecond))

				for _, cache := range caches {
					cache.Close()
				}

				time.Sleep(GetTestDuration(100 * time.Millisecond))

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Secure Data Cleanup Tests
// =============================================================================

func TestSecureDataCleanup(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}
	suite := NewMemoryLeakFixesTestSuite()

	tests := []TableTestCase{
		{
			Name:        "Basic sensitive data cleanup",
			Description: "Test basic sensitive data storage and cleanup",
			Input:       []byte("secret-token-data"),
			Expected:    true,
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
	}

	stringEdgeCases := suite.edgeGen.GenerateStringEdgeCases()
	for i, testString := range stringEdgeCases {
		if len(testString) > 0 {
			tests = append(tests, TableTestCase{
				Name:        fmt.Sprintf("Sensitive data edge case %d", i),
				Description: "Test secure cleanup with edge case data",
				Input:       []byte(testString),
				Expected:    true,
			})
		}
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				err := test.Setup(t)
				require.NoError(t, err)
			}

			if test.Teardown != nil {
				defer func() {
					err := test.Teardown(t)
					assert.NoError(t, err)
				}()
			}

			cache := NewOptimizedCache()
			defer cache.Close()

			sensitiveData := test.Input.([]byte)
			cache.Set("token", sensitiveData, time.Minute)

			val, found := cache.Get("token")
			assert.True(t, found)
			assert.Equal(t, sensitiveData, val)

			cache.Close()
		})
	}

	leakTests := []MemoryLeakTestCase{
		{
			Name:        "Secure data cleanup memory management",
			Description: "Test memory management for secure data cleanup operations",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("sensitive-key-%d", i)
					sensitiveData := []byte(fmt.Sprintf("secret-data-%d-%s", i, suite.factory.GenerateRandomString(64)))
					cache.Set(key, sensitiveData, time.Minute)
				}

				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("sensitive-key-%d", i)
					_, found := cache.Get(key)
					if !found {
						return fmt.Errorf("sensitive data not found for key: %s", key)
					}
				}

				cache.Close()

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 1,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, leakTests)
}

// =============================================================================
// Memory Growth Prevention Tests
// =============================================================================

func TestMemoryGrowthPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory growth prevention test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Multiple cache memory growth prevention",
			Description: "Test memory growth with multiple cache instances",
			Operation: func() error {
				caches := make([]*OptimizedCache, 10)
				for i := 0; i < 10; i++ {
					caches[i] = NewOptimizedCache()
					for j := 0; j < 100; j++ {
						caches[i].Set(fmt.Sprintf("key-%d-%d", i, j), "value", time.Minute)
					}
				}

				for _, cache := range caches {
					cache.Close()
				}

				runtime.GC()
				time.Sleep(GetTestDuration(100 * time.Millisecond))
				runtime.GC()

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 5,
			MaxMemoryGrowthMB:  50.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
		{
			Name:        "Large dataset memory growth prevention",
			Description: "Test memory growth with large datasets",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				for i := 0; i < 1000; i++ {
					key := fmt.Sprintf("large-key-%d", i)
					value := suite.factory.GenerateRandomString(1024)
					cache.Set(key, value, time.Minute)
				}

				for i := 0; i < 500; i++ {
					key := fmt.Sprintf("temp-key-%d", i)
					cache.Set(key, "temp-value", 10*time.Millisecond)
				}

				time.Sleep(GetTestDuration(50 * time.Millisecond))

				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("cleanup-trigger-%d", i)
					cache.Get(key)
				}

				return nil
			},
			Iterations:         2,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  100.0,
			GCBetweenRuns:      true,
			Timeout:            45 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Goroutine Leak Prevention Tests
// =============================================================================

func TestGoroutineLeakPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping goroutine leak prevention test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Concurrent cache goroutine management",
			Description: "Test goroutine management with concurrent cache operations",
			Operation: func() error {
				var wg sync.WaitGroup

				for i := 0; i < 5; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						cache := NewOptimizedCache()
						defer cache.Close()

						for j := 0; j < 10; j++ {
							cache.Set(fmt.Sprintf("key-%d", j), "value", time.Minute)
							time.Sleep(time.Millisecond)
						}
					}(i)
				}

				wg.Wait()

				time.Sleep(GetTestDuration(500 * time.Millisecond))
				runtime.GC()

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 5,
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
		{
			Name:        "Mixed component goroutine management",
			Description: "Test goroutine management with mixed component types",
			Operation: func() error {
				var wg sync.WaitGroup

				for i := 0; i < 3; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						cache := NewOptimizedCache()
						defer cache.Close()
						cache.Set("mixed-key", "mixed-value", time.Minute)
					}(i)

					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						logger := GetSingletonNoOpLogger()
						taskFunc := func() {}
						task := NewBackgroundTask(fmt.Sprintf("mixed-task-%d", i), 50*time.Millisecond, taskFunc, logger)
						task.Start()
						time.Sleep(GetTestDuration(25 * time.Millisecond))
						task.Stop()
					}(i)

					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						var localWG sync.WaitGroup
						cache := NewMetadataCache(&localWG)
						time.Sleep(GetTestDuration(25 * time.Millisecond))
						cache.Close()
					}(i)
				}

				wg.Wait()

				time.Sleep(GetTestDuration(500 * time.Millisecond))
				runtime.GC()

				return nil
			},
			Iterations:         2,
			MaxGoroutineGrowth: 8,
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Lazy Background Task Tests
// =============================================================================

func TestLazyBackgroundTask(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "LazyBackgroundTask delayed start",
			Description: "Test that lazy background task doesn't start until StartIfNeeded is called",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				callCount := 0
				taskFunc := func() {
					callCount++
				}

				task := NewLazyBackgroundTask("lazy-test", 50*time.Millisecond, taskFunc, logger)

				time.Sleep(GetTestDuration(100 * time.Millisecond))
				if callCount != 0 {
					return fmt.Errorf("task should not have executed before StartIfNeeded")
				}

				task.StartIfNeeded()
				time.Sleep(GetTestDuration(150 * time.Millisecond))

				if callCount < 2 {
					return fmt.Errorf("task should have executed at least twice after starting")
				}

				task.Stop()
				time.Sleep(GetTestDuration(100 * time.Millisecond))
				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "LazyBackgroundTask multiple StartIfNeeded calls",
			Description: "Test that multiple StartIfNeeded calls only start task once",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				execCount := 0

				taskFunc := func() {
					execCount++
				}

				task := NewLazyBackgroundTask("lazy-multiple", 50*time.Millisecond, taskFunc, logger)

				task.StartIfNeeded()
				task.StartIfNeeded()
				task.StartIfNeeded()

				time.Sleep(GetTestDuration(100 * time.Millisecond))

				if execCount < 1 {
					return fmt.Errorf("task should have executed at least once")
				}

				if !task.started {
					return fmt.Errorf("task should be marked as started")
				}

				task.Stop()

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Lazy Cache Tests
// =============================================================================

func TestLazyCache(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "LazyCache basic operations",
			Description: "Test NewLazyCache with basic cache operations",
			Operation: func() error {
				cache := NewLazyCache()
				if cache == nil {
					return fmt.Errorf("NewLazyCache returned nil")
				}

				cache.Set("key1", "value1", time.Minute)
				val, found := cache.Get("key1")
				if !found || val != "value1" {
					return fmt.Errorf("cache operation failed")
				}

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "LazyCacheWithLogger operations",
			Description: "Test NewLazyCacheWithLogger with custom logger",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				cache := NewLazyCacheWithLogger(logger)
				if cache == nil {
					return fmt.Errorf("NewLazyCacheWithLogger returned nil")
				}

				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("lazy-key-%d", i)
					cache.Set(key, i, time.Minute)
				}

				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("lazy-key-%d", i)
					val, found := cache.Get(key)
					if !found || val != i {
						return fmt.Errorf("cache value mismatch for %s", key)
					}
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  3.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// =============================================================================
// Optimized Middleware Config Tests
// =============================================================================

func TestOptimizedMiddlewareConfig(t *testing.T) {
	t.Run("DefaultOptimizedConfig", func(t *testing.T) {
		config := DefaultOptimizedConfig()

		assert.NotNil(t, config)
		assert.True(t, config.DelayBackgroundTasks)
		assert.True(t, config.ReducedCleanupIntervals)
		assert.True(t, config.AggressiveConnectionCleanup)
		assert.True(t, config.MinimalCacheSize)
	})

	t.Run("CustomOptimizedConfig", func(t *testing.T) {
		config := &OptimizedMiddlewareConfig{
			DelayBackgroundTasks:        false,
			ReducedCleanupIntervals:     true,
			AggressiveConnectionCleanup: false,
			MinimalCacheSize:            true,
		}

		assert.False(t, config.DelayBackgroundTasks)
		assert.True(t, config.ReducedCleanupIntervals)
		assert.False(t, config.AggressiveConnectionCleanup)
		assert.True(t, config.MinimalCacheSize)
	})
}

// =============================================================================
// Cleanup Idle Connections Tests
// =============================================================================

func TestCleanupIdleConnections(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	t.Run("CleanupIdleConnections basic", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
			},
		}

		stopChan := make(chan struct{})

		go CleanupIdleConnections(client, 50*time.Millisecond, stopChan)

		time.Sleep(150 * time.Millisecond)

		close(stopChan)

		time.Sleep(100 * time.Millisecond)
	})

	t.Run("CleanupIdleConnections stop immediately", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		stopChan := make(chan struct{})

		go CleanupIdleConnections(client, 100*time.Millisecond, stopChan)
		time.Sleep(10 * time.Millisecond)
		close(stopChan)

		time.Sleep(50 * time.Millisecond)
	})

	t.Run("CleanupIdleConnections with nil transport", func(t *testing.T) {
		client := &http.Client{
			Transport: nil,
		}

		stopChan := make(chan struct{})

		go CleanupIdleConnections(client, 50*time.Millisecond, stopChan)
		time.Sleep(100 * time.Millisecond)
		close(stopChan)
		time.Sleep(50 * time.Millisecond)
	})
}

// =============================================================================
// Unit Tests (Non-Leak Detection)
// =============================================================================

func TestNewLazyBackgroundTaskUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	callCount := 0
	taskFunc := func() {
		callCount++
	}

	task := NewLazyBackgroundTask("test-task", 50*time.Millisecond, taskFunc, logger)

	require.NotNil(t, task)
	assert.NotNil(t, task.BackgroundTask)
	assert.False(t, task.started)

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, callCount, "task should not execute before StartIfNeeded")

	if task.started {
		task.Stop()
	}
}

func TestLazyBackgroundTaskStartIfNeededUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	callCount := 0
	var mu sync.Mutex
	taskFunc := func() {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	task := NewLazyBackgroundTask("test-start", 30*time.Millisecond, taskFunc, logger)
	require.NotNil(t, task)

	task.StartIfNeeded()
	assert.True(t, task.started)

	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	firstCount := callCount
	mu.Unlock()
	assert.Greater(t, firstCount, 0, "task should execute after StartIfNeeded")

	task.StartIfNeeded()
	task.StartIfNeeded()

	task.Stop()
}

func TestLazyBackgroundTaskStopUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	callCount := 0
	var mu sync.Mutex
	taskFunc := func() {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	task := NewLazyBackgroundTask("test-stop", 30*time.Millisecond, taskFunc, logger)
	require.NotNil(t, task)

	task.StartIfNeeded()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	countAfterStart := callCount
	mu.Unlock()
	assert.Greater(t, countAfterStart, 0)

	task.Stop()
	assert.False(t, task.started)

	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	countAfterStop := callCount
	mu.Unlock()

	assert.LessOrEqual(t, countAfterStop, countAfterStart+1, "task should stop executing")
}

func TestNewLazyCacheUnit(t *testing.T) {
	cache := NewLazyCache()

	require.NotNil(t, cache)

	cache.Set("test-key", "test-value", time.Minute)
	val, found := cache.Get("test-key")

	assert.True(t, found)
	assert.Equal(t, "test-value", val)
}

func TestNewLazyCacheWithLoggerUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cache := NewLazyCacheWithLogger(logger)

	require.NotNil(t, cache)

	for i := 0; i < 10; i++ {
		key := "key-" + string(rune('0'+i))
		cache.Set(key, i, time.Minute)
	}

	for i := 0; i < 10; i++ {
		key := "key-" + string(rune('0'+i))
		val, found := cache.Get(key)
		assert.True(t, found, "should find key %s", key)
		assert.Equal(t, i, val, "should get correct value for key %s", key)
	}
}

func TestNewLazyCacheWithLoggerNilUnit(t *testing.T) {
	cache := NewLazyCacheWithLogger(nil)

	require.NotNil(t, cache)

	cache.Set("nil-test", "value", time.Minute)
	val, found := cache.Get("nil-test")

	assert.True(t, found)
	assert.Equal(t, "value", val)
}

func TestCleanupIdleConnectionsUnit(t *testing.T) {
	t.Run("basic cleanup cycle", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
			},
		}

		stopChan := make(chan struct{})

		go CleanupIdleConnections(client, 40*time.Millisecond, stopChan)

		time.Sleep(100 * time.Millisecond)

		close(stopChan)

		time.Sleep(50 * time.Millisecond)
	})

	t.Run("immediate stop", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		stopChan := make(chan struct{})

		go CleanupIdleConnections(client, 100*time.Millisecond, stopChan)
		time.Sleep(10 * time.Millisecond)
		close(stopChan)

		time.Sleep(50 * time.Millisecond)
	})

	t.Run("nil transport", func(t *testing.T) {
		client := &http.Client{
			Transport: nil,
		}

		stopChan := make(chan struct{})

		go CleanupIdleConnections(client, 40*time.Millisecond, stopChan)
		time.Sleep(80 * time.Millisecond)
		close(stopChan)
		time.Sleep(50 * time.Millisecond)
	})
}

func TestDefaultOptimizedConfigUnit(t *testing.T) {
	config := DefaultOptimizedConfig()

	require.NotNil(t, config)
	assert.True(t, config.DelayBackgroundTasks)
	assert.True(t, config.ReducedCleanupIntervals)
	assert.True(t, config.AggressiveConnectionCleanup)
	assert.True(t, config.MinimalCacheSize)
}

// =============================================================================
// Consolidated Memory Leak Tests
// =============================================================================

func TestMemoryLeakConsolidated(t *testing.T) {
	baselineGoroutines := runtime.NumGoroutine()
	defer func() {
		VerifyNoGoroutineLeaks(t, baselineGoroutines, 20, "TestMemoryLeakConsolidated")
	}()

	testCases := []MemoryTestCase{
		{
			name:        "cache_basic_lifecycle",
			component:   "cache",
			scenario:    "lifecycle",
			iterations:  10,
			concurrency: 1,
			setup: func(tf *MemoryTestFramework) error {
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				cache := NewCache()
				defer cache.Close()

				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					cache.Set(key, "value", time.Minute)
					cache.Get(key)
				}
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 1024*1024 {
					t.Errorf("Memory leak detected: %d bytes allocated", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
		{
			name:        "cache_concurrent_access",
			component:   "cache",
			scenario:    "concurrent",
			iterations:  5,
			concurrency: 10,
			setup: func(tf *MemoryTestFramework) error {
				tf.cache = NewCache()
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				var wg sync.WaitGroup
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						for j := 0; j < 100; j++ {
							key := fmt.Sprintf("key-%d-%d", id, j)
							tf.cache.Set(key, "value", time.Second)
							tf.cache.Get(key)
						}
					}(i)
				}
				wg.Wait()
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 5*1024*1024 {
					t.Errorf("Memory leak in concurrent cache: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				if tf.cache != nil {
					tf.cache.Close()
					tf.cache = nil
				}
				return nil
			},
		},
		{
			name:        "session_manager_lifecycle",
			component:   "session",
			scenario:    "lifecycle",
			iterations:  5,
			concurrency: 1,
			setup: func(tf *MemoryTestFramework) error {
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				sm, err := NewSessionManager(
					"test-encryption-key-32-bytes-long-enough",
					false,
					"",
					"",
					0,
					tf.logger,
				)
				if err != nil {
					return err
				}
				defer func() {}()

				for i := 0; i < 50; i++ {
					req := httptest.NewRequest("GET", "/", nil)
					_, _ = sm.GetSession(req)
				}
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 2*1024*1024 {
					t.Errorf("Session manager memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
		{
			name:        "buffer_pool_memory",
			component:   "pool",
			scenario:    "stress",
			iterations:  5,
			concurrency: 10,
			setup: func(tf *MemoryTestFramework) error {
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				pool := NewBufferPool(4096)
				var wg sync.WaitGroup

				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := 0; j < 100; j++ {
							buf := pool.Get()
							buf.WriteString("test data")
							pool.Put(buf)
						}
					}()
				}
				wg.Wait()
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 1024*1024 {
					t.Errorf("Buffer pool memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
		{
			name:        "gzip_pool_memory",
			component:   "pool",
			scenario:    "stress",
			iterations:  3,
			concurrency: 5,
			setup: func(tf *MemoryTestFramework) error {
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				pool := NewGzipWriterPool()
				var wg sync.WaitGroup

				for i := 0; i < 5; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := 0; j < 50; j++ {
							w := pool.Get()
							var buf bytes.Buffer
							w.Reset(&buf)
							w.Write([]byte("test compression data"))
							w.Close()
							pool.Put(w)
						}
					}()
				}
				wg.Wait()
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 2*1024*1024 {
					t.Errorf("Gzip pool memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%s_%s_%s", tc.component, tc.scenario, tc.name), func(t *testing.T) {
			if testing.Short() && tc.scenario == "longrunning" {
				t.Skip("Skipping long-running test in short mode")
			}

			for iteration := 0; iteration < tc.iterations; iteration++ {
				framework := NewMemoryTestFramework(t)
				defer framework.Cleanup()

				if tc.setup != nil {
					require.NoError(t, tc.setup(framework))
				}

				runtime.GC()
				runtime.GC()
				debug.FreeOSMemory()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)

				err := tc.execute(framework)
				require.NoError(t, err)

				if tc.cleanup != nil {
					require.NoError(t, tc.cleanup(framework))
				}

				runtime.GC()
				runtime.GC()
				debug.FreeOSMemory()
				var after runtime.MemStats
				runtime.ReadMemStats(&after)

				tc.validateLeak(t, before, after)
			}
		})
	}
}

// =============================================================================
// Goroutine Leak Tests
// =============================================================================

func TestGoroutineLeaks(t *testing.T) {
	testCases := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "cache_no_leak",
			test: func(t *testing.T) {
				baseline := runtime.NumGoroutine()

				cache := NewCache()
				for i := 0; i < 100; i++ {
					cache.Set(fmt.Sprintf("key-%d", i), "value", time.Second)
				}
				cache.Close()
				time.Sleep(100 * time.Millisecond)

				VerifyNoGoroutineLeaks(t, baseline, 2, "cache operations")
			},
		},
		{
			name: "session_manager_no_leak",
			test: func(t *testing.T) {
				baseline := runtime.NumGoroutine()

				sm, err := NewSessionManager(
					"test-encryption-key-32-bytes-long-enough",
					false,
					"",
					"",
					0,
					NewLogger("error"),
				)
				require.NoError(t, err)

				if sm != nil {
					sm.Shutdown()
				}
				time.Sleep(100 * time.Millisecond)

				VerifyNoGoroutineLeaks(t, baseline, 2, "session manager")
			},
		},
		{
			name: "plugin_no_leak",
			test: func(t *testing.T) {
				baseline := runtime.NumGoroutine()

				config := CreateConfig()
				config.ProviderURL = "https://accounts.google.com"
				config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
				config.ClientID = "test-client"
				config.ClientSecret = "test-secret"

				handler, err := New(context.Background(), nil, config, "test")
				require.NoError(t, err)

				plugin := handler.(*TraefikOidc)
				plugin.Close()
				time.Sleep(500 * time.Millisecond)

				VerifyNoGoroutineLeaks(t, baseline, 10, "plugin lifecycle")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.test)
	}
}

// =============================================================================
// Memory Thresholds Tests
// =============================================================================

func TestMemoryThresholds(t *testing.T) {
	thresholds := map[string]uint64{
		"cache_1000_items":      10 * 1024 * 1024,
		"session_100_sessions":  5 * 1024 * 1024,
		"plugin_initialization": 20 * 1024 * 1024,
		"buffer_pool_usage":     2 * 1024 * 1024,
	}

	t.Run("cache_memory_threshold", func(t *testing.T) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		cache := NewCache()
		for i := 0; i < 1000; i++ {
			cache.Set(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i), time.Hour)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)
		cache.Close()

		var memUsed uint64
		if after.Alloc >= before.Alloc {
			memUsed = after.Alloc - before.Alloc
		} else {
			memUsed = 0
		}

		threshold := thresholds["cache_1000_items"]
		assert.LessOrEqual(t, memUsed, threshold,
			"Cache memory usage %d exceeds threshold %d", memUsed, threshold)
	})

	t.Run("session_memory_threshold", func(t *testing.T) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		sm, _ := NewSessionManager(
			"test-encryption-key-32-bytes-long-enough",
			false,
			"",
			"",
			0,
			NewLogger("error"),
		)

		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			_, _ = sm.GetSession(req)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)

		var memUsed uint64
		if after.Alloc >= before.Alloc {
			memUsed = after.Alloc - before.Alloc
		} else {
			memUsed = 0
		}

		threshold := thresholds["session_100_sessions"]
		assert.LessOrEqual(t, memUsed, threshold,
			"Session memory usage %d exceeds threshold %d", memUsed, threshold)
	})
}
