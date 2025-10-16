package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewJWKCache tests JWK cache creation
func TestNewJWKCache(t *testing.T) {
	cache := NewJWKCache()

	require.NotNil(t, cache)
	assert.NotNil(t, cache.cache, "cache should have underlying universal cache")
}

// TestJWKCacheGetJWKS tests JWKS fetching and caching
func TestJWKCacheGetJWKS(t *testing.T) {
	t.Run("fetch from remote on cache miss", func(t *testing.T) {
		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{
				Keys: []JWK{
					{
						Kid: "key1",
						Kty: "RSA",
						Use: "sig",
						Alg: "RS256",
						N:   "test-n-value",
						E:   "AQAB",
					},
				},
			}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx := context.Background()
		client := http.DefaultClient

		jwks, err := cache.GetJWKS(ctx, server.URL, client)

		require.NoError(t, err)
		require.NotNil(t, jwks)
		assert.Len(t, jwks.Keys, 1)
		assert.Equal(t, "key1", jwks.Keys[0].Kid)
		assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	})

	t.Run("return cached value on cache hit", func(t *testing.T) {
		fetchCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fetchCount++
			jwks := JWKSet{
				Keys: []JWK{
					{Kid: "key1", Kty: "RSA"},
				},
			}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx := context.Background()
		client := http.DefaultClient

		// First fetch - should hit server
		jwks1, err1 := cache.GetJWKS(ctx, server.URL, client)
		require.NoError(t, err1)
		assert.Equal(t, 1, fetchCount, "should fetch from server on first call")

		// Second fetch - should use cache
		jwks2, err2 := cache.GetJWKS(ctx, server.URL, client)
		require.NoError(t, err2)
		assert.Equal(t, 1, fetchCount, "should not fetch from server on second call")

		// Both should return same data
		assert.Equal(t, jwks1.Keys[0].Kid, jwks2.Keys[0].Kid)
	})

	t.Run("handle server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx := context.Background()
		client := http.DefaultClient

		jwks, err := cache.GetJWKS(ctx, server.URL, client)

		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("handle empty JWKS", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{Keys: []JWK{}}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx := context.Background()
		client := http.DefaultClient

		jwks, err := cache.GetJWKS(ctx, server.URL, client)

		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "no keys")
	})

	t.Run("handle invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx := context.Background()
		client := http.DefaultClient

		jwks, err := cache.GetJWKS(ctx, server.URL, client)

		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "parsing")
	})

	t.Run("handle multiple keys", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{
				Keys: []JWK{
					{Kid: "key1", Kty: "RSA", Alg: "RS256"},
					{Kid: "key2", Kty: "RSA", Alg: "RS256"},
					{Kid: "key3", Kty: "EC", Alg: "ES256"},
				},
			}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx := context.Background()
		client := http.DefaultClient

		jwks, err := cache.GetJWKS(ctx, server.URL, client)

		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 3)
		assert.Equal(t, "key1", jwks.Keys[0].Kid)
		assert.Equal(t, "key2", jwks.Keys[1].Kid)
		assert.Equal(t, "key3", jwks.Keys[2].Kid)
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Create server that delays response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			jwks := JWKSet{Keys: []JWK{{Kid: "key1"}}}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache := NewJWKCache()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		client := http.DefaultClient

		jwks, err := cache.GetJWKS(ctx, server.URL, client)

		assert.Error(t, err)
		assert.Nil(t, jwks)
	})
}

// TestJWKSetGetKey tests the GetKey method
func TestJWKSetGetKey(t *testing.T) {
	jwks := &JWKSet{
		Keys: []JWK{
			{Kid: "key1", Kty: "RSA", Alg: "RS256"},
			{Kid: "key2", Kty: "RSA", Alg: "RS384"},
			{Kid: "key3", Kty: "EC", Alg: "ES256"},
		},
	}

	t.Run("find existing key", func(t *testing.T) {
		key := jwks.GetKey("key2")

		require.NotNil(t, key)
		assert.Equal(t, "key2", key.Kid)
		assert.Equal(t, "RS384", key.Alg)
	})

	t.Run("return nil for non-existent key", func(t *testing.T) {
		key := jwks.GetKey("non-existent")

		assert.Nil(t, key)
	})

	t.Run("find first key", func(t *testing.T) {
		key := jwks.GetKey("key1")

		require.NotNil(t, key)
		assert.Equal(t, "key1", key.Kid)
	})

	t.Run("find last key", func(t *testing.T) {
		key := jwks.GetKey("key3")

		require.NotNil(t, key)
		assert.Equal(t, "key3", key.Kid)
		assert.Equal(t, "EC", key.Kty)
	})

	t.Run("empty key set returns nil", func(t *testing.T) {
		emptyJWKS := &JWKSet{Keys: []JWK{}}
		key := emptyJWKS.GetKey("any-key")

		assert.Nil(t, key)
	})

	t.Run("case sensitive key ID", func(t *testing.T) {
		key1 := jwks.GetKey("key1")
		key2 := jwks.GetKey("KEY1")

		assert.NotNil(t, key1)
		assert.Nil(t, key2, "key ID lookup should be case sensitive")
	})
}

// TestJWKCacheCleanupAndClose tests the no-op Cleanup and Close methods
func TestJWKCacheCleanupAndClose(t *testing.T) {
	cache := NewJWKCache()
	require.NotNil(t, cache)

	t.Run("cleanup is safe to call", func(t *testing.T) {
		assert.NotPanics(t, func() {
			cache.Cleanup()
		})
	})

	t.Run("close is safe to call", func(t *testing.T) {
		assert.NotPanics(t, func() {
			cache.Close()
		})
	})

	t.Run("multiple cleanup calls are safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			cache.Cleanup()
			cache.Cleanup()
			cache.Cleanup()
		})
	})

	t.Run("multiple close calls are safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			cache.Close()
			cache.Close()
			cache.Close()
		})
	})

	t.Run("operations work after cleanup", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{Keys: []JWK{{Kid: "key1", Kty: "RSA"}}}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache.Cleanup()

		// Should still work
		jwks, err := cache.GetJWKS(context.Background(), server.URL, http.DefaultClient)
		assert.NoError(t, err)
		assert.NotNil(t, jwks)
	})

	t.Run("operations work after close", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{Keys: []JWK{{Kid: "key2", Kty: "RSA"}}}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache.Close()

		// Should still work (close is a no-op)
		jwks, err := cache.GetJWKS(context.Background(), server.URL, http.DefaultClient)
		assert.NoError(t, err)
		assert.NotNil(t, jwks)
	})
}

// TestFetchJWKS tests the fetchJWKS helper function indirectly through GetJWKS
func TestFetchJWKSEdgeCases(t *testing.T) {
	t.Run("handles various HTTP status codes", func(t *testing.T) {
		testCases := []struct {
			status      int
			wantErr     bool
			errContains string
		}{
			{200, false, ""},
			{400, true, "400"},
			{401, true, "401"},
			{403, true, "403"},
			{404, true, "404"},
			{500, true, "500"},
			{502, true, "502"},
			{503, true, "503"},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("status_%d", tc.status), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.status)
					if tc.status == 200 {
						jwks := JWKSet{Keys: []JWK{{Kid: "key1"}}}
						json.NewEncoder(w).Encode(jwks)
					} else {
						w.Write([]byte("error"))
					}
				}))
				defer server.Close()

				cache := NewJWKCache()
				jwks, err := cache.GetJWKS(context.Background(), server.URL, http.DefaultClient)

				if tc.wantErr {
					assert.Error(t, err)
					if tc.errContains != "" {
						assert.Contains(t, err.Error(), tc.errContains)
					}
					assert.Nil(t, jwks)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, jwks)
				}
			})
		}
	})

	t.Run("handles response body reading", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write valid JSON
			jwks := JWKSet{
				Keys: []JWK{
					{Kid: "test-key", Kty: "RSA", Alg: "RS256"},
				},
			}
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		cache := NewJWKCache()
		jwks, err := cache.GetJWKS(context.Background(), server.URL, http.DefaultClient)

		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 1)
	})
}

// TestJWKCacheConcurrency tests concurrent access to JWK cache
func TestJWKCacheConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		time.Sleep(10 * time.Millisecond) // Simulate some processing
		jwks := JWKSet{Keys: []JWK{{Kid: "key1", Kty: "RSA"}}}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := NewJWKCache()
	const numGoroutines = 10

	// Launch multiple concurrent requests
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			jwks, err := cache.GetJWKS(context.Background(), server.URL, http.DefaultClient)
			assert.NoError(t, err)
			assert.NotNil(t, jwks)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// With caching and mutex protection, server should only be hit once or very few times
	// (may be hit more than once due to race between first requests)
	assert.LessOrEqual(t, fetchCount, 3, "should use cache for most requests")
}
