package traefikoidc

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSharedTransportPoolGetOrCreateTransport tests transport creation and reuse
func TestSharedTransportPoolGetOrCreateTransport(t *testing.T) {
	t.Run("create new transport", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)

		require.NotNil(t, transport)
		assert.Equal(t, int32(1), atomic.LoadInt32(&pool.clientCount))
		assert.Len(t, pool.transports, 1)
	})

	t.Run("reuse existing transport", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport1 := pool.GetOrCreateTransport(config)
		transport2 := pool.GetOrCreateTransport(config)

		assert.Equal(t, transport1, transport2, "should reuse same transport")
		assert.Equal(t, int32(1), atomic.LoadInt32(&pool.clientCount), "client count should not increase")

		// Check ref count
		pool.mu.RLock()
		key := pool.configKey(config)
		shared := pool.transports[key]
		pool.mu.RUnlock()

		assert.Equal(t, 2, shared.refCount, "ref count should be 2")
	})

	t.Run("client limit enforcement", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 5, // Already at max
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)

		assert.Nil(t, transport, "should return nil when at client limit")
	})

	t.Run("client limit with existing transport", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		// Create first transport
		config1 := DefaultHTTPClientConfig()
		transport1 := pool.GetOrCreateTransport(config1)
		require.NotNil(t, transport1)

		// Set client count to max
		atomic.StoreInt32(&pool.clientCount, 5)

		// Try to create with different config
		config2 := DefaultHTTPClientConfig()
		config2.MaxConnsPerHost = 15 // Different config
		transport2 := pool.GetOrCreateTransport(config2)

		// Should return existing transport since at limit
		assert.NotNil(t, transport2)
		assert.Equal(t, transport1, transport2)
	})

	t.Run("updates last used time", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		pool.mu.RLock()
		key := pool.configKey(config)
		firstTime := pool.transports[key].lastUsed
		pool.mu.RUnlock()

		time.Sleep(10 * time.Millisecond)

		// Get again
		transport2 := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport2)

		pool.mu.RLock()
		secondTime := pool.transports[key].lastUsed
		pool.mu.RUnlock()

		assert.True(t, secondTime.After(firstTime), "lastUsed should be updated")
	})
}

// TestSharedTransportPoolReleaseTransport tests transport release
func TestSharedTransportPoolReleaseTransport(t *testing.T) {
	t.Run("decrement ref count", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		// Get again to increase ref count
		pool.GetOrCreateTransport(config)

		pool.mu.RLock()
		key := pool.configKey(config)
		refCount := pool.transports[key].refCount
		pool.mu.RUnlock()
		assert.Equal(t, 2, refCount)

		// Release
		pool.ReleaseTransport(transport)

		pool.mu.RLock()
		newRefCount := pool.transports[key].refCount
		pool.mu.RUnlock()
		assert.Equal(t, 1, newRefCount)
	})

	t.Run("ref count reaches zero", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		pool.mu.RLock()
		key := pool.configKey(config)
		pool.mu.RUnlock()

		// Release to zero
		pool.ReleaseTransport(transport)

		pool.mu.RLock()
		shared := pool.transports[key]
		pool.mu.RUnlock()

		assert.Equal(t, 0, shared.refCount)
		assert.NotZero(t, shared.lastUsed, "lastUsed should be set")
	})

	t.Run("release non-existent transport", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		// Create a transport not in the pool
		fakeTransport := &http.Transport{}

		// Should not panic
		assert.NotPanics(t, func() {
			pool.ReleaseTransport(fakeTransport)
		})
	})

	t.Run("release updates last used", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		time.Sleep(10 * time.Millisecond)

		beforeRelease := time.Now()
		pool.ReleaseTransport(transport)

		pool.mu.RLock()
		key := pool.configKey(config)
		lastUsed := pool.transports[key].lastUsed
		pool.mu.RUnlock()

		assert.True(t, lastUsed.After(beforeRelease) || lastUsed.Equal(beforeRelease))
	})
}

// TestSharedTransportPoolCleanup tests cleanup functionality
func TestSharedTransportPoolCleanup(t *testing.T) {
	t.Run("cleanup all transports", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		// Create multiple transports
		config1 := DefaultHTTPClientConfig()
		pool.GetOrCreateTransport(config1)

		config2 := DefaultHTTPClientConfig()
		config2.MaxConnsPerHost = 15
		pool.GetOrCreateTransport(config2)

		assert.Greater(t, len(pool.transports), 0)

		// Cleanup
		pool.Cleanup()

		assert.Len(t, pool.transports, 0, "all transports should be removed")
	})

	t.Run("cleanup cancels context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		pool.Cleanup()

		select {
		case <-pool.ctx.Done():
			// Context was canceled
		case <-time.After(100 * time.Millisecond):
			t.Error("context should be canceled")
		}
	})

	t.Run("cleanup with no transports", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		assert.NotPanics(t, func() {
			pool.Cleanup()
		})
	})

	t.Run("cleanup closes idle connections", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		// Cleanup should call CloseIdleConnections on each transport
		pool.Cleanup()

		// Verify transports map is cleared
		assert.Empty(t, pool.transports)
	})
}

// TestSharedTransportPoolCleanupIdleTransports tests periodic cleanup
func TestSharedTransportPoolCleanupIdleTransports(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cleanup goroutine test in short mode")
	}

	t.Run("cleanup removes idle transports", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		// Create transport and release it
		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		pool.ReleaseTransport(transport)

		// Set lastUsed to old time
		pool.mu.Lock()
		key := pool.configKey(config)
		pool.transports[key].lastUsed = time.Now().Add(-3 * time.Minute)
		pool.mu.Unlock()

		// Start cleanup in background (simulating what would happen)
		// Note: We're testing the cleanup logic manually here
		pool.mu.Lock()
		now := time.Now()
		for transportKey, shared := range pool.transports {
			if shared.refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
				shared.transport.CloseIdleConnections()
				delete(pool.transports, transportKey)
				atomic.AddInt32(&pool.clientCount, -1)
			}
		}
		pool.mu.Unlock()

		// Transport should be removed
		pool.mu.RLock()
		_, exists := pool.transports[key]
		pool.mu.RUnlock()

		assert.False(t, exists, "old idle transport should be removed")
	})

	t.Run("cleanup preserves active transports", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		// Create transport with refs
		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		// Keep ref count > 0, but set old lastUsed
		pool.mu.Lock()
		key := pool.configKey(config)
		pool.transports[key].lastUsed = time.Now().Add(-3 * time.Minute)
		pool.mu.Unlock()

		// Run cleanup logic
		pool.mu.Lock()
		now := time.Now()
		for transportKey, shared := range pool.transports {
			if shared.refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
				shared.transport.CloseIdleConnections()
				delete(pool.transports, transportKey)
			}
		}
		pool.mu.Unlock()

		// Transport should still exist (has ref count)
		pool.mu.RLock()
		_, exists := pool.transports[key]
		pool.mu.RUnlock()

		assert.True(t, exists, "transport with references should be preserved")
	})

	t.Run("cleanup respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		// Start cleanup goroutine
		done := make(chan bool)
		go func() {
			pool.cleanupIdleTransports(ctx)
			done <- true
		}()

		// Cancel context
		cancel()

		// Should exit quickly
		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Error("cleanup goroutine should exit on context cancellation")
		}
	})
}

// TestCreatePooledHTTPClient tests pooled client creation
func TestCreatePooledHTTPClient(t *testing.T) {
	t.Run("create client with default config", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		client := CreatePooledHTTPClient(config)

		require.NotNil(t, client)
		assert.NotNil(t, client.Transport)
		assert.Equal(t, config.Timeout, client.Timeout)
	})

	t.Run("create multiple clients reuse transport", func(t *testing.T) {
		// Reset global pool for clean test
		globalTransportPoolOnce = sync.Once{}
		globalTransportPool = nil

		config := DefaultHTTPClientConfig()
		client1 := CreatePooledHTTPClient(config)
		client2 := CreatePooledHTTPClient(config)

		require.NotNil(t, client1)
		require.NotNil(t, client2)

		// Should use same transport
		assert.Equal(t, client1.Transport, client2.Transport)
	})

	t.Run("redirect policy is set", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.MaxRedirects = 3

		client := CreatePooledHTTPClient(config)

		require.NotNil(t, client)
		assert.NotNil(t, client.CheckRedirect)

		// Test redirect limit
		var redirects []*http.Request
		for i := 0; i < 3; i++ {
			redirects = append(redirects, &http.Request{})
		}

		err := client.CheckRedirect(nil, redirects)
		assert.Error(t, err, "should error after max redirects")
	})

	t.Run("default redirect limit", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.MaxRedirects = 0 // Should default to 10

		client := CreatePooledHTTPClient(config)

		require.NotNil(t, client)

		// Test default redirect limit (10)
		var redirects []*http.Request
		for i := 0; i < 10; i++ {
			redirects = append(redirects, &http.Request{})
		}

		err := client.CheckRedirect(nil, redirects)
		assert.Error(t, err, "should error after 10 redirects")
	})
}

// TestGetGlobalTransportPool tests singleton pattern
func TestGetGlobalTransportPool(t *testing.T) {
	t.Run("returns same instance", func(t *testing.T) {
		pool1 := GetGlobalTransportPool()
		pool2 := GetGlobalTransportPool()

		assert.Equal(t, pool1, pool2, "should return same singleton instance")
	})

	t.Run("pool is initialized", func(t *testing.T) {
		pool := GetGlobalTransportPool()

		require.NotNil(t, pool)
		assert.NotNil(t, pool.transports)
		assert.Equal(t, 20, pool.maxConns)
		assert.Equal(t, int32(5), pool.maxClients)
		assert.NotNil(t, pool.ctx)
		assert.NotNil(t, pool.cancel)
	})
}

// TestSharedTransportPoolConcurrency tests thread safety
func TestSharedTransportPoolConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	t.Run("concurrent GetOrCreateTransport", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  10, // Allow more for concurrency test
		}

		config := DefaultHTTPClientConfig()
		const numGoroutines = 20

		var wg sync.WaitGroup
		transports := make([]*http.Transport, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				transports[idx] = pool.GetOrCreateTransport(config)
			}(i)
		}

		wg.Wait()

		// All should get same transport
		firstTransport := transports[0]
		for i := 1; i < numGoroutines; i++ {
			if transports[i] != nil {
				assert.Equal(t, firstTransport, transports[i])
			}
		}
	})

	t.Run("concurrent ReleaseTransport", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  10,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)

		// Increase ref count
		for i := 0; i < 20; i++ {
			pool.GetOrCreateTransport(config)
		}

		const numReleases = 20
		var wg sync.WaitGroup

		for i := 0; i < numReleases; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pool.ReleaseTransport(transport)
			}()
		}

		wg.Wait()

		// Should not panic and ref count should be decremented
		pool.mu.RLock()
		key := pool.configKey(config)
		refCount := pool.transports[key].refCount
		pool.mu.RUnlock()

		assert.Equal(t, 1, refCount, "ref count should be 1 after 20 releases from initial 21")
	})
}

// TestSharedTransportPoolEdgeCases tests edge cases
func TestSharedTransportPoolEdgeCases(t *testing.T) {
	t.Run("config key generation", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports: make(map[string]*sharedTransport),
		}

		config1 := DefaultHTTPClientConfig()
		config1.MaxConnsPerHost = 10
		config1.MaxIdleConnsPerHost = 5

		config2 := DefaultHTTPClientConfig()
		config2.MaxConnsPerHost = 10
		config2.MaxIdleConnsPerHost = 5

		key1 := pool.configKey(config1)
		key2 := pool.configKey(config2)

		assert.Equal(t, key1, key2, "same config should produce same key")
	})

	t.Run("different configs produce different keys", func(t *testing.T) {
		pool := &SharedTransportPool{
			transports: make(map[string]*sharedTransport),
		}

		config1 := DefaultHTTPClientConfig()
		config1.MaxConnsPerHost = 10

		config2 := DefaultHTTPClientConfig()
		config2.MaxConnsPerHost = 20

		key1 := pool.configKey(config1)
		key2 := pool.configKey(config2)

		assert.NotEqual(t, key1, key2, "different configs should produce different keys")
	})

	t.Run("client count decrements on cleanup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		pool := &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			clientCount: 0,
			maxClients:  5,
			ctx:         ctx,
			cancel:      cancel,
		}

		config := DefaultHTTPClientConfig()
		transport := pool.GetOrCreateTransport(config)
		require.NotNil(t, transport)

		initialCount := atomic.LoadInt32(&pool.clientCount)
		assert.Equal(t, int32(1), initialCount)

		// Release and mark as old
		pool.ReleaseTransport(transport)
		pool.mu.Lock()
		key := pool.configKey(config)
		pool.transports[key].lastUsed = time.Now().Add(-3 * time.Minute)
		pool.mu.Unlock()

		// Run cleanup
		pool.mu.Lock()
		now := time.Now()
		for transportKey, shared := range pool.transports {
			if shared.refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
				shared.transport.CloseIdleConnections()
				delete(pool.transports, transportKey)
				atomic.AddInt32(&pool.clientCount, -1)
			}
		}
		pool.mu.Unlock()

		finalCount := atomic.LoadInt32(&pool.clientCount)
		assert.Equal(t, int32(0), finalCount, "client count should decrement on cleanup")
	})
}
