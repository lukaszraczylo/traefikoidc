package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSharedTransportPool(t *testing.T) {
	t.Run("singleton pattern", func(t *testing.T) {
		pool1 := GetGlobalTransportPool()
		pool2 := GetGlobalTransportPool()

		if pool1 != pool2 {
			t.Error("GetGlobalTransportPool should return the same instance")
		}
	})

	t.Run("transport reuse", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports: make(map[string]*sharedTransport),
			maxConns:   100,
		}

		config := DefaultHTTPClientConfig()

		// Get transport twice with same config
		transport1 := pool.GetOrCreateTransport(config)
		transport2 := pool.GetOrCreateTransport(config)

		if transport1 != transport2 {
			t.Error("Should reuse the same transport for identical configs")
		}

		// Check reference count
		pool.mu.RLock()
		var refCount int
		for _, shared := range pool.transports {
			if shared.transport == transport1 {
				refCount = shared.refCount
				break
			}
		}
		pool.mu.RUnlock()

		if refCount != 2 {
			t.Errorf("Expected refCount 2, got %d", refCount)
		}
	})

	t.Run("transport release", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports: make(map[string]*sharedTransport),
			maxConns:   100,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)

		// Release the transport
		pool.ReleaseTransport(transport)

		// Check reference count
		pool.mu.RLock()
		var refCount int
		for _, shared := range pool.transports {
			if shared.transport == transport {
				refCount = shared.refCount
				break
			}
		}
		pool.mu.RUnlock()

		if refCount != 0 {
			t.Errorf("Expected refCount 0 after release, got %d", refCount)
		}
	})

	t.Run("cleanup", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports: make(map[string]*sharedTransport),
			maxConns:   100,
		}

		config := DefaultHTTPClientConfig()
		_ = pool.GetOrCreateTransport(config)

		// Cleanup should clear all transports
		pool.Cleanup()

		if len(pool.transports) != 0 {
			t.Errorf("Expected 0 transports after cleanup, got %d", len(pool.transports))
		}
	})
}

func TestCreatePooledHTTPClient(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	t.Run("basic functionality", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		client := CreatePooledHTTPClient(config)

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("concurrent requests", func(t *testing.T) {
		config := DefaultHTTPClientConfig()

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				client := CreatePooledHTTPClient(config)
				resp, err := client.Get(server.URL)
				if err != nil {
					t.Errorf("Failed to make request: %v", err)
					return
				}
				resp.Body.Close()
			}()
		}
		wg.Wait()
	})

	t.Run("timeout configuration", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.Timeout = 100 * time.Millisecond

		// Create a slow server
		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer slowServer.Close()

		client := CreatePooledHTTPClient(config)
		_, err := client.Get(slowServer.URL)

		if err == nil {
			t.Error("Expected timeout error")
		}
	})
}

func TestSharedTransportPoolRaceConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping race condition test in short mode")
	}

	pool := &SharedTransportPool{
		transports: make(map[string]*sharedTransport),
		maxConns:   100,
	}

	var wg sync.WaitGroup

	// Concurrent get/create operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			config := DefaultHTTPClientConfig()
			config.MaxConnsPerHost = id % 5 // Create some variety

			transport := pool.GetOrCreateTransport(config)
			time.Sleep(10 * time.Millisecond)
			pool.ReleaseTransport(transport)
		}(i)
	}

	// Concurrent cleanup operations
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
			pool.Cleanup()
		}()
	}

	wg.Wait()
}
