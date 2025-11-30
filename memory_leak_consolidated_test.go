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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	t            *testing.T
	cache        CacheInterface
	sessionMgr   *SessionManager
	plugin       *TraefikOidc
	logger       *Logger
	servers      []*httptest.Server
	configs      []*Config
	ctx          context.Context
	cancel       context.CancelFunc
	requestCount int64
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
	// Wait for goroutines to settle
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
	runtime.GC() // Double GC for accuracy
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

// TestMemoryLeakConsolidated runs all memory leak test scenarios
func TestMemoryLeakConsolidated(t *testing.T) {
	// Check for goroutine leaks at the test level
	baselineGoroutines := runtime.NumGoroutine()
	defer func() {
		VerifyNoGoroutineLeaks(t, baselineGoroutines, 20, "TestMemoryLeakConsolidated")
	}()

	testCases := []MemoryTestCase{
		// Cache memory tests
		{
			name:        "cache_basic_lifecycle",
			component:   "cache",
			scenario:    "lifecycle",
			iterations:  10,
			concurrency: 1,
			setup: func(tf *MemoryTestFramework) error {
				// No setup needed
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				cache := NewCache()
				defer cache.Close()

				// Perform basic cache operations
				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					cache.Set(key, "value", time.Minute)
					cache.Get(key)
				}
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 1024*1024 { // 1MB threshold
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
				for i := 0; i < 10; i++ { // Using fixed concurrency value
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
				if allocDiff > 5*1024*1024 { // 5MB threshold for concurrent
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
			name:        "cache_eviction_memory",
			component:   "cache",
			scenario:    "stress",
			iterations:  3,
			concurrency: 1,
			setup: func(tf *MemoryTestFramework) error {
				tf.cache = NewCache()
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				// Fill cache beyond capacity to trigger eviction
				for i := 0; i < 10000; i++ {
					key := fmt.Sprintf("evict-key-%d", i)
					value := fmt.Sprintf("value-%d", i)
					tf.cache.Set(key, value, time.Minute)
				}

				// Force cleanup
				runtime.GC()
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				// After eviction, memory should be reclaimed
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 10*1024*1024 { // 10MB threshold
					t.Errorf("Memory not reclaimed after eviction: %d bytes", allocDiff)
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

		// Session memory tests
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
				// SessionManager doesn't have a Cleanup method, just let it be GC'd
				defer func() {
					// No explicit cleanup needed
				}()

				// Create and destroy sessions
				for i := 0; i < 50; i++ {
					req := httptest.NewRequest("GET", "/", nil)
					_, _ = sm.GetSession(req)
					// Session is managed internally by SessionManager
				}
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 2*1024*1024 { // 2MB threshold
					t.Errorf("Session manager memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
		{
			name:        "session_pool_reuse",
			component:   "session",
			scenario:    "concurrent",
			iterations:  3,
			concurrency: 20,
			setup: func(tf *MemoryTestFramework) error {
				var err error
				tf.sessionMgr, err = NewSessionManager(
					"test-encryption-key-32-bytes-long-enough",
					false,
					"",
					"",
					0,
					tf.logger,
				)
				return err
			},
			execute: func(tf *MemoryTestFramework) error {
				var wg sync.WaitGroup
				for i := 0; i < 20; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						for j := 0; j < 100; j++ {
							req := httptest.NewRequest("GET", "/", nil)
							_, _ = tf.sessionMgr.GetSession(req)
							// Session is managed internally
						}
					}(i)
				}
				wg.Wait()
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 5*1024*1024 { // 5MB threshold
					t.Errorf("Session pool memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				if tf.sessionMgr != nil {
					// No Cleanup method available
					tf.sessionMgr = nil
				}
				return nil
			},
		},

		// Token/Plugin memory tests
		{
			name:        "plugin_lifecycle_memory",
			component:   "plugin",
			scenario:    "lifecycle",
			iterations:  3,
			concurrency: 1,
			setup: func(tf *MemoryTestFramework) error {
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				config := CreateConfig()
				config.ProviderURL = "https://accounts.google.com"
				config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
				config.ClientID = "test-client"
				config.ClientSecret = "test-secret"

				handler, err := New(tf.ctx, nil, config, "test")
				if err != nil {
					return err
				}

				plugin := handler.(*TraefikOidc)
				defer plugin.Close()

				// Simulate some usage
				time.Sleep(100 * time.Millisecond)
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 10*1024*1024 { // 10MB threshold
					t.Errorf("Plugin lifecycle memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
		{
			name:        "plugin_request_processing",
			component:   "plugin",
			scenario:    "stress",
			iterations:  2,
			concurrency: 10,
			setup: func(tf *MemoryTestFramework) error {
				// Create mock OIDC provider
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/.well-known/openid-configuration" {
						w.Header().Set("Content-Type", "application/json")
						w.Write([]byte(`{
							"issuer": "` + r.Host + `",
							"authorization_endpoint": "` + r.Host + `/auth",
							"token_endpoint": "` + r.Host + `/token",
							"userinfo_endpoint": "` + r.Host + `/userinfo",
							"jwks_uri": "` + r.Host + `/jwks"
						}`))
					}
				}))
				tf.servers = append(tf.servers, server)

				config := CreateConfig()
				config.ProviderURL = server.URL
				config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
				config.ClientID = "test-client"
				config.ClientSecret = "test-secret"

				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})

				handler, err := New(tf.ctx, next, config, "test")
				if err != nil {
					return err
				}
				tf.plugin = handler.(*TraefikOidc)
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				var wg sync.WaitGroup
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := 0; j < 100; j++ {
							req := httptest.NewRequest("GET", "/test", nil)
							w := httptest.NewRecorder()
							tf.plugin.ServeHTTP(w, req)
							atomic.AddInt64(&tf.requestCount, 1)
						}
					}()
				}
				wg.Wait()
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 20*1024*1024 { // 20MB threshold for stress test
					t.Errorf("Plugin request processing leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				if tf.plugin != nil {
					tf.plugin.Close()
					tf.plugin = nil
				}
				return nil
			},
		},

		// Memory pool tests
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
				if allocDiff > 1024*1024 { // 1MB threshold
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
				if allocDiff > 2*1024*1024 { // 2MB threshold
					t.Errorf("Gzip pool memory leak: %d bytes", allocDiff)
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},

		// Long-running scenario tests
		{
			name:        "cache_longrunning_cleanup",
			component:   "cache",
			scenario:    "longrunning",
			iterations:  1,
			concurrency: 1,
			setup: func(tf *MemoryTestFramework) error {
				tf.cache = NewCache()
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				// Simulate long-running cache with periodic operations
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()

				timeout := time.After(2 * time.Second)
				i := 0

				for {
					select {
					case <-ticker.C:
						key := fmt.Sprintf("long-key-%d", i)
						tf.cache.Set(key, "value", 500*time.Millisecond)
						tf.cache.Get(key)
						i++
					case <-timeout:
						return nil
					}
				}
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 5*1024*1024 { // 5MB threshold
					t.Errorf("Long-running cache memory leak: %d bytes", allocDiff)
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
			name:        "production_simulation_80_hosts",
			component:   "plugin",
			scenario:    "longrunning",
			iterations:  1,
			concurrency: 80,
			setup: func(tf *MemoryTestFramework) error {
				// Create 80 virtual host configurations
				for i := 0; i < 80; i++ {
					config := CreateConfig()
					config.ProviderURL = fmt.Sprintf("https://provider%d.example.com", i)
					config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
					config.ClientID = fmt.Sprintf("client-%d", i)
					config.ClientSecret = "test-secret"
					tf.configs = append(tf.configs, config)
				}
				return nil
			},
			execute: func(tf *MemoryTestFramework) error {
				plugins := make([]*TraefikOidc, len(tf.configs))

				// Create all plugin instances
				for i, config := range tf.configs {
					handler, err := New(tf.ctx, nil, config, fmt.Sprintf("host-%d", i))
					if err != nil {
						return err
					}
					plugins[i] = handler.(*TraefikOidc)
				}

				// Simulate traffic
				var wg sync.WaitGroup
				for i := range plugins {
					wg.Add(1)
					go func(p *TraefikOidc) {
						defer wg.Done()
						for j := 0; j < 10; j++ {
							req := httptest.NewRequest("GET", "/", nil)
							w := httptest.NewRecorder()
							p.ServeHTTP(w, req)
						}
					}(plugins[i])
				}
				wg.Wait()

				// Cleanup all plugins
				for _, p := range plugins {
					p.Close()
				}
				return nil
			},
			validateLeak: func(t *testing.T, before, after runtime.MemStats) {
				allocDiff := int64(after.Alloc) - int64(before.Alloc)
				if allocDiff > 100*1024*1024 { // 100MB threshold for 80 hosts
					t.Errorf("Production simulation memory leak: %d MB", allocDiff/(1024*1024))
				}
			},
			cleanup: func(tf *MemoryTestFramework) error {
				return nil
			},
		},
	}

	// Run all test cases
	for _, tc := range testCases {
		tc := tc // Capture loop variable
		t.Run(fmt.Sprintf("%s_%s_%s", tc.component, tc.scenario, tc.name), func(t *testing.T) {
			// Skip long-running tests in short mode
			if testing.Short() && tc.scenario == "longrunning" {
				t.Skip("Skipping long-running test in short mode")
			}

			for iteration := 0; iteration < tc.iterations; iteration++ {
				framework := NewMemoryTestFramework(t)
				defer framework.Cleanup()

				// Setup
				if tc.setup != nil {
					require.NoError(t, tc.setup(framework))
				}

				// Take baseline memory snapshot
				runtime.GC()
				runtime.GC()
				debug.FreeOSMemory()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)

				// Execute test
				err := tc.execute(framework)
				require.NoError(t, err)

				// Cleanup
				if tc.cleanup != nil {
					require.NoError(t, tc.cleanup(framework))
				}

				// Take final memory snapshot
				runtime.GC()
				runtime.GC()
				debug.FreeOSMemory()
				var after runtime.MemStats
				runtime.ReadMemStats(&after)

				// Validate memory usage
				tc.validateLeak(t, before, after)
			}
		})
	}
}

// BenchmarkMemoryUsage provides memory benchmarks for key operations
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("Cache_Operations", func(b *testing.B) {
		b.ReportAllocs()
		cache := NewCache()
		defer cache.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench-key-%d", i)
			cache.Set(key, "value", time.Minute)
			cache.Get(key)
			cache.Delete(key)
		}
	})

	b.Run("Session_Creation", func(b *testing.B) {
		b.ReportAllocs()
		sm, _ := NewSessionManager(
			"test-encryption-key-32-bytes-long-enough",
			false,
			"",
			"",
			0,
			NewLogger("error"),
		)
		// No Cleanup method, defer not needed

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			_, _ = sm.GetSession(req)
			// Session is managed internally
		}
	})

	b.Run("Buffer_Pool", func(b *testing.B) {
		b.ReportAllocs()
		pool := NewBufferPool(4096)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := pool.Get()
			buf.WriteString("benchmark data")
			pool.Put(buf)
		}
	})

	b.Run("Plugin_Request", func(b *testing.B) {
		b.ReportAllocs()
		config := CreateConfig()
		config.ProviderURL = "https://accounts.google.com"
		config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler, _ := New(context.Background(), next, config, "bench")
		plugin := handler.(*TraefikOidc)
		defer plugin.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			plugin.ServeHTTP(w, req)
		}
	})
}

// TestGoroutineLeaks verifies no goroutine leaks across components
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

				// Properly shutdown the session manager
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
				// Give more time for goroutines to clean up
				time.Sleep(500 * time.Millisecond)

				// Allow more tolerance for HTTP client goroutines and background tasks
				VerifyNoGoroutineLeaks(t, baseline, 10, "plugin lifecycle")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.test)
	}
}

// TestMemoryThresholds validates memory usage stays within acceptable bounds
func TestMemoryThresholds(t *testing.T) {
	thresholds := map[string]uint64{
		"cache_1000_items":      10 * 1024 * 1024, // 10MB
		"session_100_sessions":  5 * 1024 * 1024,  // 5MB
		"plugin_initialization": 20 * 1024 * 1024, // 20MB
		"buffer_pool_usage":     2 * 1024 * 1024,  // 2MB
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

		// Handle potential underflow when after.Alloc < before.Alloc (can happen after GC)
		var memUsed uint64
		if after.Alloc >= before.Alloc {
			memUsed = after.Alloc - before.Alloc
		} else {
			// Memory decreased after GC, which is acceptable - set to 0
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
			// Session is managed internally
		}

		runtime.GC()
		runtime.ReadMemStats(&after)
		// No Cleanup method available

		// Handle potential underflow when after.Alloc < before.Alloc (can happen after GC)
		var memUsed uint64
		if after.Alloc >= before.Alloc {
			memUsed = after.Alloc - before.Alloc
		} else {
			// Memory decreased after GC, which is acceptable - set to 0
			memUsed = 0
		}

		threshold := thresholds["session_100_sessions"]
		assert.LessOrEqual(t, memUsed, threshold,
			"Session memory usage %d exceeds threshold %d", memUsed, threshold)
	})
}
