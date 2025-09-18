package httpclient

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFactoryCreateClient(t *testing.T) {
	factory := NewFactory(nil)

	// Test creating default client
	client, err := factory.CreateDefault()
	if err != nil {
		t.Fatalf("Failed to create default client: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Test creating token client
	tokenClient, err := factory.CreateToken()
	if err != nil {
		t.Fatalf("Failed to create token client: %v", err)
	}
	if tokenClient == nil {
		t.Fatal("Expected non-nil token client")
	}
}

func TestFactoryCreateClientWithPreset(t *testing.T) {
	factory := NewFactory(nil)

	testCases := []struct {
		name       string
		clientType ClientType
		shouldFail bool
	}{
		{"Default", ClientTypeDefault, false},
		{"Token", ClientTypeToken, false},
		{"API", ClientTypeAPI, false},
		{"Proxy", ClientTypeProxy, false},
		{"Invalid", ClientType("invalid"), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := factory.CreateClientWithPreset(tc.clientType)
			if tc.shouldFail {
				if err == nil {
					t.Fatal("Expected error for invalid client type")
				}
			} else {
				if err != nil {
					t.Fatalf("Failed to create %s client: %v", tc.clientType, err)
				}
				if client == nil {
					t.Fatal("Expected non-nil client")
				}
			}
		})
	}
}

func TestFactoryValidateConfig(t *testing.T) {
	factory := NewFactory(nil)

	testCases := []struct {
		name       string
		config     Config
		shouldFail bool
	}{
		{
			name:       "Valid config",
			config:     PresetConfigs[ClientTypeDefault],
			shouldFail: false,
		},
		{
			name: "Negative MaxIdleConns",
			config: Config{
				MaxIdleConns: -1,
			},
			shouldFail: true,
		},
		{
			name: "Excessive MaxIdleConns",
			config: Config{
				MaxIdleConns: 2000,
			},
			shouldFail: true,
		},
		{
			name: "Negative timeout",
			config: Config{
				Timeout: -1 * time.Second,
			},
			shouldFail: true,
		},
		{
			name: "Excessive timeout",
			config: Config{
				Timeout: 10 * time.Minute,
			},
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := factory.ValidateConfig(&tc.config)
			if tc.shouldFail && err == nil {
				t.Fatal("Expected validation to fail")
			}
			if !tc.shouldFail && err != nil {
				t.Fatalf("Unexpected validation error: %v", err)
			}
		})
	}
}

func TestTransportPoolConcurrency(t *testing.T) {
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		clientCount: 0,
		maxClients:  5,
	}

	config := PresetConfigs[ClientTypeDefault]

	var wg sync.WaitGroup
	numGoroutines := 10

	// Test concurrent transport creation
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			transport := pool.GetOrCreateTransport(config)
			if transport != nil {
				// Simulate usage
				time.Sleep(10 * time.Millisecond)
				pool.Release(transport)
			}
		}()
	}
	wg.Wait()

	// Verify client count is within limits
	clientCount := atomic.LoadInt32(&pool.clientCount)
	if clientCount > pool.maxClients {
		t.Fatalf("Client count %d exceeds max %d", clientCount, pool.maxClients)
	}
}

func TestHTTPClientRequests(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	factory := NewFactory(nil)
	client, err := factory.CreateDefault()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestClientWithCookieJar(t *testing.T) {
	config := PresetConfigs[ClientTypeToken]
	if !config.UseCookieJar {
		t.Skip("Token client should have cookie jar enabled")
	}

	factory := NewFactory(nil)
	client, err := factory.CreateToken()
	if err != nil {
		t.Fatalf("Failed to create token client: %v", err)
	}

	if client.Jar == nil {
		t.Fatal("Expected cookie jar to be set")
	}
}

func TestTransportPoolCleanup(t *testing.T) {
	pool := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		clientCount: 0,
		maxClients:  5,
	}

	config := PresetConfigs[ClientTypeDefault]

	// Create transport
	transport := pool.GetOrCreateTransport(config)
	if transport == nil {
		t.Fatal("Failed to create transport")
	}

	// Release transport
	pool.Release(transport)

	// Simulate idle time
	pool.mu.Lock()
	for _, shared := range pool.transports {
		shared.lastUsed = time.Now().Add(-11 * time.Minute)
		atomic.StoreInt32(&shared.refCount, 0)
	}
	pool.mu.Unlock()

	// Run cleanup
	pool.cleanupIdle()

	// Verify transport was removed
	pool.mu.RLock()
	count := len(pool.transports)
	pool.mu.RUnlock()

	if count != 0 {
		t.Fatalf("Expected 0 transports after cleanup, got %d", count)
	}
}

func TestGlobalFactorySingleton(t *testing.T) {
	factory1 := GetGlobalFactory(nil)
	factory2 := GetGlobalFactory(nil)

	if factory1 != factory2 {
		t.Fatal("Expected singleton factory instances to be the same")
	}
}

func TestCompatibilityFunctions(t *testing.T) {
	// Test CreateDefaultHTTPClient
	defaultClient := CreateDefaultHTTPClient()
	if defaultClient == nil {
		t.Fatal("Expected non-nil default client")
	}

	// Test CreateTokenHTTPClient
	tokenClient := CreateTokenHTTPClient()
	if tokenClient == nil {
		t.Fatal("Expected non-nil token client")
	}

	// Test CreateHTTPClientWithConfig
	config := PresetConfigs[ClientTypeAPI]
	apiClient := CreateHTTPClientWithConfig(config)
	if apiClient == nil {
		t.Fatal("Expected non-nil API client")
	}
}

func BenchmarkFactoryCreateClient(b *testing.B) {
	factory := NewFactory(nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			client, err := factory.CreateDefault()
			if err != nil || client == nil {
				b.Fatal("Failed to create client")
			}
		}
	})
}

func BenchmarkTransportPoolGetOrCreate(b *testing.B) {
	pool := GetGlobalTransportPool()
	config := PresetConfigs[ClientTypeDefault]

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			transport := pool.GetOrCreateTransport(config)
			if transport != nil {
				pool.Release(transport)
			}
		}
	})
}
