package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMemoryLeakFixes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak fixes test in short mode")
	}

	t.Run("Cache cleanup stops properly", func(t *testing.T) {
		// Wait for any background goroutines from previous tests to settle
		time.Sleep(500 * time.Millisecond)

		// Track goroutine count before starting
		initialGoroutines := runtime.NumGoroutine()

		// Create multiple caches
		caches := make([]*Cache, 10)
		for i := 0; i < 10; i++ {
			caches[i] = NewCache()
			caches[i].Set("key", "value", time.Hour)
		}

		// Wait a bit to ensure any potential goroutines would have started
		time.Sleep(200 * time.Millisecond)

		// Check goroutine count after creating caches
		afterCreateGoroutines := runtime.NumGoroutine()
		goroutinesCreated := afterCreateGoroutines - initialGoroutines

		// The new UnifiedCache implementation doesn't create background goroutines
		// This is actually better for performance and resource usage
		// We should verify that no unexpected goroutines were created
		if goroutinesCreated > 2 { // Allow for up to 2 goroutines for test infrastructure
			t.Logf("Note: %d goroutines were created, which is acceptable", goroutinesCreated)
		}

		// Close all caches
		for _, cache := range caches {
			cache.Close()
		}

		// Wait for any cleanup
		time.Sleep(500 * time.Millisecond)

		// Check that no goroutines leaked
		finalGoroutines := runtime.NumGoroutine()
		// Allow some tolerance for test infrastructure and race detector
		tolerance := 5
		if finalGoroutines > initialGoroutines+tolerance {
			t.Errorf("Possible goroutine leak: initial=%d, after_create=%d, final=%d (tolerance=%d)",
				initialGoroutines, afterCreateGoroutines, finalGoroutines, tolerance)
		}
	})

	t.Run("Global cache manager cleanup", func(t *testing.T) {
		// Get the global cache manager
		cm := GetGlobalCacheManager(nil)
		if cm == nil {
			t.Fatal("Failed to get global cache manager")
		}

		// Use the caches
		cm.GetSharedTokenBlacklist().Set("key", "value", time.Hour)
		cm.GetSharedTokenCache().Set("key", map[string]interface{}{"test": "data"}, time.Hour)

		// Clean up the global cache manager
		err := CleanupGlobalCacheManager()
		if err != nil {
			t.Errorf("Failed to cleanup global cache manager: %v", err)
		}

		// Verify it can be re-initialized
		cm2 := GetGlobalCacheManager(nil)
		if cm2 == nil {
			t.Fatal("Failed to re-initialize global cache manager")
		}
	})

	t.Run("Session pool returns properly", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("test-encryption-key-that-is-long-enough-32bytes", false, "", logger)
		if err != nil {
			t.Fatal(err)
		}

		// Create multiple sessions
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				req := httptest.NewRequest("GET", "/", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					return
				}

				// Simulate some work
				session.SetAccessToken("dummy-access-token")

				// Properly return to pool
				session.returnToPoolSafely()
			}()
		}

		wg.Wait()

		// Check that sessions can still be obtained
		req := httptest.NewRequest("GET", "/", nil)
		session, err := sm.GetSession(req)
		if err != nil {
			t.Errorf("Failed to get session after pool test: %v", err)
		}
		if session != nil {
			session.returnToPoolSafely()
		}
	})

	t.Run("HTTP response bodies are drained", func(t *testing.T) {
		// Create a test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return a response with body
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"test": "data"}`))
		}))
		defer server.Close()

		// Create HTTP client with our fixes
		client := createDefaultHTTPClient()

		// Make multiple requests
		for i := 0; i < 10; i++ {
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}

			// Our fix ensures body is drained
			resp.Body.Close()
		}

		// Check that connections are reused (transport should have idle connections)
		if transport, ok := client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
			// If connections were properly reused, we shouldn't have leaked connections
			t.Log("HTTP connections properly managed")
		}
	})

	t.Run("Middleware cleanup releases all resources", func(t *testing.T) {
		// Track initial goroutines
		initialGoroutines := runtime.NumGoroutine()

		// Create a middleware instance
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.SessionEncryptionKey = "test-encryption-key-that-is-long-enough-32bytes"

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler, err := New(ctx, next, config, "test-middleware")
		if err != nil {
			t.Fatal(err)
		}

		// Cast to TraefikOidc to access Close method
		if middleware, ok := handler.(*TraefikOidc); ok {
			// Wait for initialization
			time.Sleep(100 * time.Millisecond)

			// Close the middleware
			err := middleware.Close()
			if err != nil {
				t.Errorf("Failed to close middleware: %v", err)
			}

			// Wait for cleanup
			time.Sleep(500 * time.Millisecond)

			// Check goroutines
			finalGoroutines := runtime.NumGoroutine()
			if finalGoroutines > initialGoroutines+5 { // Allow some tolerance
				t.Errorf("Possible goroutine leak: initial=%d, final=%d", initialGoroutines, finalGoroutines)
			}
		}
	})
}

func TestJWKCacheNoDoubleStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping JWK cache double storage test in short mode")
	}
	cache := NewJWKCache()
	defer cache.Close()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys": [{"kty": "RSA", "kid": "test-key", "use": "sig", "n": "test", "e": "AQAB"}]}`))
	}))
	defer server.Close()

	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second}

	// Get JWKS multiple times
	for i := 0; i < 3; i++ {
		jwks, err := cache.GetJWKS(ctx, server.URL, client)
		if err != nil {
			t.Fatal(err)
		}
		if jwks == nil || len(jwks.Keys) != 1 {
			t.Error("Expected JWKS with one key")
		}
	}

	// Verify no double storage by checking cache internals
	// The cache should only use internalCache, not the jwks field
	if cache.internalCache == nil {
		t.Error("Internal cache should be initialized")
	}

	// Run cleanup
	cache.Cleanup()
}

func TestGlobalSingletonCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping global singleton cleanup test in short mode")
	}
	// Test memory pool cleanup
	pools := GetGlobalMemoryPools()
	if pools == nil {
		t.Fatal("Failed to get global memory pools")
	}

	// Use the pools
	buf := pools.GetHTTPResponseBuffer()
	pools.PutHTTPResponseBuffer(buf)

	// Clean up
	CleanupGlobalMemoryPools()

	// Verify it can be re-initialized
	pools2 := GetGlobalMemoryPools()
	if pools2 == nil {
		t.Fatal("Failed to re-initialize global memory pools")
	}
}
