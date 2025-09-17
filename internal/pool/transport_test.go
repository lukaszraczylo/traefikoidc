package pool

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestGetTransportPool_Singleton tests that GetTransportPool returns the same instance
func TestGetTransportPool_Singleton(t *testing.T) {
	pool1 := GetTransportPool()
	pool2 := GetTransportPool()

	if pool1 != pool2 {
		t.Error("GetTransportPool() should return the same instance (singleton)")
	}

	if pool1 == nil {
		t.Error("GetTransportPool() should not return nil")
	}
}

// TestDefaultTransportConfig tests the default transport configuration
func TestDefaultTransportConfig(t *testing.T) {
	config := DefaultTransportConfig()

	// Verify security defaults
	if config.MinTLSVersion != tls.VersionTLS12 {
		t.Errorf("Default MinTLSVersion should be TLS 1.2, got %d", config.MinTLSVersion)
	}

	if config.InsecureSkipVerify {
		t.Error("Default should not skip TLS verification")
	}

	if !config.ForceHTTP2 {
		t.Error("Default should force HTTP/2")
	}

	// Verify reasonable timeouts
	if config.DialTimeout <= 0 {
		t.Error("DialTimeout should be positive")
	}

	if config.TLSHandshakeTimeout <= 0 {
		t.Error("TLSHandshakeTimeout should be positive")
	}

	if config.ResponseHeaderTimeout <= 0 {
		t.Error("ResponseHeaderTimeout should be positive")
	}

	// Verify connection limits
	if config.MaxIdleConns <= 0 {
		t.Error("MaxIdleConns should be positive")
	}

	if config.MaxIdleConnsPerHost <= 0 {
		t.Error("MaxIdleConnsPerHost should be positive")
	}

	if config.MaxConnsPerHost <= 0 {
		t.Error("MaxConnsPerHost should be positive")
	}
}

// TestTransportPool_GetTransport tests transport creation and reuse
func TestTransportPool_GetTransport(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	config := DefaultTransportConfig()

	// First call should create new transport
	transport1 := pool.GetTransport(config)
	if transport1 == nil {
		t.Error("GetTransport should not return nil")
	}

	// Second call with same config should return same transport
	transport2 := pool.GetTransport(config)
	if transport2 == nil {
		t.Error("GetTransport should not return nil")
	}

	if transport1 != transport2 {
		t.Error("GetTransport should return same transport for same config")
	}

	// Verify reference counting
	pool.mu.RLock()
	key := pool.configKey(config)
	shared := pool.transports[key]
	refCount := shared.refCount
	pool.mu.RUnlock()

	if refCount != 2 {
		t.Errorf("Reference count should be 2, got %d", refCount)
	}
}

// TestTransportPool_GetTransport_DifferentConfigs tests transport creation with different configs
func TestTransportPool_GetTransport_DifferentConfigs(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	config1 := DefaultTransportConfig()
	config2 := DefaultTransportConfig()
	config2.MaxConnsPerHost = 10 // Different from default

	transport1 := pool.GetTransport(config1)
	transport2 := pool.GetTransport(config2)

	if transport1 == transport2 {
		t.Error("Different configs should produce different transports")
	}
}

// TestTransportPool_GetTransport_ClientLimit tests client limit enforcement
func TestTransportPool_GetTransport_ClientLimit(t *testing.T) {
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		maxClients:  2, // Low limit for testing
		clientCount: 2, // Already at limit
	}

	config := DefaultTransportConfig()

	// Should return existing transport when limit reached
	transport := pool.GetTransport(config)
	// Transport might be nil if no existing transports
	if transport != nil && pool.clientCount > pool.maxClients {
		t.Error("Should not exceed client limit")
	}
}

// TestTransportPool_ReleaseTransport tests transport reference counting
func TestTransportPool_ReleaseTransport(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	config := DefaultTransportConfig()

	// Get transport
	transport := pool.GetTransport(config)
	if transport == nil {
		t.Error("GetTransport should not return nil")
	}

	// Release transport
	pool.ReleaseTransport(transport)

	// Verify reference count decreased
	pool.mu.RLock()
	key := pool.configKey(config)
	shared := pool.transports[key]
	refCount := shared.refCount
	pool.mu.RUnlock()

	if refCount != 0 {
		t.Errorf("Reference count should be 0 after release, got %d", refCount)
	}
}

// TestTransportPool_ReleaseTransport_Nil tests releasing nil transport
func TestTransportPool_ReleaseTransport_Nil(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	// Should not panic
	pool.ReleaseTransport(nil)
}

// TestTransportPool_ReleaseTransport_Unknown tests releasing unknown transport
func TestTransportPool_ReleaseTransport_Unknown(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	// Create a transport not from the pool
	transport := &http.Transport{}

	// Should not panic
	pool.ReleaseTransport(transport)
}

// TestTransportPool_createTransport tests transport creation with different configs
func TestTransportPool_createTransport(t *testing.T) {
	pool := &TransportPool{}

	tests := []struct {
		name   string
		config TransportConfig
	}{
		{
			"default config",
			DefaultTransportConfig(),
		},
		{
			"custom timeouts",
			TransportConfig{
				DialTimeout:         10 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
				MinTLSVersion:       tls.VersionTLS13,
			},
		},
		{
			"insecure config",
			TransportConfig{
				InsecureSkipVerify: true,
				MinTLSVersion:      tls.VersionTLS10,
			},
		},
		{
			"no HTTP/2",
			TransportConfig{
				ForceHTTP2: false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := pool.createTransport(test.config)

			if transport == nil {
				t.Error("createTransport should not return nil")
				return
			}

			// Verify TLS config
			if transport.TLSClientConfig == nil {
				t.Error("Transport should have TLS config")
				return
			}

			// Verify minimum TLS version
			expectedMinVersion := test.config.MinTLSVersion
			if expectedMinVersion == 0 {
				expectedMinVersion = tls.VersionTLS12 // Default
			}
			if transport.TLSClientConfig.MinVersion != expectedMinVersion {
				t.Errorf("TLS MinVersion should be %d, got %d", expectedMinVersion, transport.TLSClientConfig.MinVersion)
			}

			// Verify max TLS version
			if transport.TLSClientConfig.MaxVersion != tls.VersionTLS13 {
				t.Errorf("TLS MaxVersion should be %d, got %d", tls.VersionTLS13, transport.TLSClientConfig.MaxVersion)
			}

			// Verify InsecureSkipVerify
			if transport.TLSClientConfig.InsecureSkipVerify != test.config.InsecureSkipVerify {
				t.Errorf("InsecureSkipVerify should be %v, got %v", test.config.InsecureSkipVerify, transport.TLSClientConfig.InsecureSkipVerify)
			}

			// Verify HTTP/2
			if transport.ForceAttemptHTTP2 != test.config.ForceHTTP2 {
				t.Errorf("ForceAttemptHTTP2 should be %v, got %v", test.config.ForceHTTP2, transport.ForceAttemptHTTP2)
			}

			// Verify timeouts
			if test.config.TLSHandshakeTimeout > 0 && transport.TLSHandshakeTimeout != test.config.TLSHandshakeTimeout {
				t.Errorf("TLSHandshakeTimeout should be %v, got %v", test.config.TLSHandshakeTimeout, transport.TLSHandshakeTimeout)
			}
		})
	}
}

// TestTransportPool_configKey tests configuration key generation
func TestTransportPool_configKey(t *testing.T) {
	pool := &TransportPool{}

	config1 := DefaultTransportConfig()
	config2 := DefaultTransportConfig()

	key1 := pool.configKey(config1)
	key2 := pool.configKey(config2)

	if key1 != key2 {
		t.Error("Same configs should generate same key")
	}

	// Different config
	config3 := config1
	config3.MaxConnsPerHost = 999
	key3 := pool.configKey(config3)

	if key1 == key3 {
		t.Error("Different configs should generate different keys")
	}
}

// TestTransportPool_cleanupIdle tests idle transport cleanup
func TestTransportPool_cleanupIdle(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
	}

	config := DefaultTransportConfig()
	transport := pool.createTransport(config)

	// Add transport to pool with old timestamp
	shared := &sharedTransport{
		transport: transport,
		refCount:  0,
		lastUsed:  time.Now().Add(-5 * time.Minute), // Old
		config:    config,
	}

	key := pool.configKey(config)
	pool.transports[key] = shared

	// Run cleanup
	pool.cleanupIdle()

	// Transport should be removed
	if _, exists := pool.transports[key]; exists {
		t.Error("Old idle transport should be cleaned up")
	}
}

// TestTransportPool_cleanup tests full cleanup
func TestTransportPool_cleanup(t *testing.T) {
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		maxClients:  5,
		clientCount: 3,
	}

	config := DefaultTransportConfig()
	transport := pool.createTransport(config)

	// Add transport to pool
	shared := &sharedTransport{
		transport: transport,
		refCount:  1,
		lastUsed:  time.Now(),
		config:    config,
	}

	key := pool.configKey(config)
	pool.transports[key] = shared

	// Run cleanup
	pool.cleanup()

	// All transports should be removed
	if len(pool.transports) != 0 {
		t.Error("All transports should be cleaned up")
	}

	// Client count should be reset
	if pool.clientCount != 0 {
		t.Error("Client count should be reset")
	}
}

// TestTransportPool_Shutdown tests graceful shutdown
func TestTransportPool_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 5,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Should not panic
	pool.Shutdown()
}

// TestTransportPool_GetStats tests statistics
func TestTransportPool_GetStats(t *testing.T) {
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		maxClients:  5,
		clientCount: 3,
	}

	config := DefaultTransportConfig()

	// Add some transports
	for i := 0; i < 3; i++ {
		transport := pool.createTransport(config)
		shared := &sharedTransport{
			transport: transport,
			refCount:  int32(i % 2), // Some active, some idle
			lastUsed:  time.Now(),
			config:    config,
		}
		pool.transports[string(rune(i))] = shared
	}

	stats := pool.GetStats()

	if stats.TotalClients != 3 {
		t.Errorf("TotalClients should be 3, got %d", stats.TotalClients)
	}

	if stats.MaxClients != 5 {
		t.Errorf("MaxClients should be 5, got %d", stats.MaxClients)
	}

	if stats.ActiveTransports < 0 || stats.ActiveTransports > 3 {
		t.Errorf("ActiveTransports should be between 0 and 3, got %d", stats.ActiveTransports)
	}
}

// TestCreateHTTPClient tests HTTP client creation
func TestCreateHTTPClient(t *testing.T) {
	config := DefaultTransportConfig()
	timeout := 30 * time.Second

	client := CreateHTTPClient(config, timeout)

	if client == nil {
		t.Error("CreateHTTPClient should not return nil")
		return
	}

	if client.Timeout != timeout {
		t.Errorf("Client timeout should be %v, got %v", timeout, client.Timeout)
	}

	if client.Transport == nil {
		t.Error("Client should have transport")
	}

	if client.CheckRedirect == nil {
		t.Error("Client should have redirect policy")
	}

	// Test redirect policy
	req := &http.Request{}
	var via []*http.Request

	// Should allow up to 9 redirects (10 total requests)
	for i := 0; i < 9; i++ {
		via = append(via, &http.Request{})
		err := client.CheckRedirect(req, via)
		if err != nil {
			t.Errorf("Should allow %d redirects, got error: %v", i+1, err)
		}
	}

	// Should reject 10th redirect (11th total request)
	via = append(via, &http.Request{})
	err := client.CheckRedirect(req, via)
	if err != http.ErrUseLastResponse {
		t.Error("Should reject too many redirects")
	}
}

// TestCreateHTTPClient_Fallback tests fallback when pool is exhausted
func TestCreateHTTPClient_Fallback(t *testing.T) {
	// Override global pool with limited one
	originalPool := globalTransportPool
	defer func() {
		globalTransportPool = originalPool
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	globalTransportPool = &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		ctx:         ctx,
		cancel:      cancel,
		clientCount: 10,
		maxClients:  1, // Very low limit
	}

	config := DefaultTransportConfig()
	timeout := 30 * time.Second

	client := CreateHTTPClient(config, timeout)

	if client == nil {
		t.Error("CreateHTTPClient should not return nil even when pool is exhausted")
		return
	}

	if client.Timeout != timeout {
		t.Errorf("Client timeout should be %v, got %v", timeout, client.Timeout)
	}
}

// TestTransportPool_ConcurrentAccess tests concurrent access to transport pool
func TestTransportPool_ConcurrentAccess(t *testing.T) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 50, // High limit for concurrent test
	}

	// Use different configs to reduce contention on single transport
	baseConfig := DefaultTransportConfig()
	configs := make([]TransportConfig, 10)
	for i := range configs {
		configs[i] = baseConfig
		configs[i].MaxConnsPerHost = 5 + i // Make each config unique
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	operationsPerGoroutine := 3

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			config := configs[goroutineID%len(configs)]
			for j := 0; j < operationsPerGoroutine; j++ {
				transport := pool.GetTransport(config)
				if transport == nil {
					continue
				}
				// Use transport briefly
				time.Sleep(time.Millisecond)
				pool.ReleaseTransport(transport)
			}
		}(i)
	}

	wg.Wait()

	// Should not panic and should have reasonable stats
	stats := pool.GetStats()
	if stats.TotalClients < 0 || stats.TotalClients > int32(numGoroutines) {
		t.Errorf("Unexpected client count: %d", stats.TotalClients)
	}
}

// Benchmark tests for performance verification
func BenchmarkTransportPool_GetTransport(b *testing.B) {
	pool := &TransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   20,
		maxClients: 100,
	}

	config := DefaultTransportConfig()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		transport := pool.GetTransport(config)
		pool.ReleaseTransport(transport)
	}
}

func BenchmarkCreateHTTPClient(b *testing.B) {
	config := DefaultTransportConfig()
	timeout := 30 * time.Second
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		CreateHTTPClient(config, timeout)
	}
}

func BenchmarkTransportPool_configKey(b *testing.B) {
	pool := &TransportPool{}
	config := DefaultTransportConfig()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pool.configKey(config)
	}
}
