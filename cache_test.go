package traefikoidc

import (
	"reflect"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	t.Run("Basic Set and Get", func(t *testing.T) {
		cache := NewCache()
		key := "test-key"
		value := "test-value"
		expiration := 1 * time.Second

		// Test Set
		cache.Set(key, value, expiration)

		// Test Get
		got, found := cache.Get(key)
		if !found {
			t.Error("Expected to find key in cache")
		}
		if got != value {
			t.Errorf("Expected value %v, got %v", value, got)
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		cache := NewCache()
		key := "test-key"
		value := "test-value"
		expiration := 10 * time.Millisecond

		// Set with short expiration
		cache.Set(key, value, expiration)

		// Wait for expiration
		time.Sleep(20 * time.Millisecond)

		// Should not find expired key
		_, found := cache.Get(key)
		if found {
			t.Error("Expected key to be expired")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		cache := NewCache()
		key := "test-key"
		value := "test-value"
		expiration := 1 * time.Second

		// Set and then delete
		cache.Set(key, value, expiration)
		cache.Delete(key)

		// Should not find deleted key
		_, found := cache.Get(key)
		if found {
			t.Error("Expected key to be deleted")
		}
	})

	t.Run("Cleanup", func(t *testing.T) {
		cache := NewCache()
		// Add multiple items with different expirations
		cache.Set("expired1", "value1", 10*time.Millisecond)
		cache.Set("expired2", "value2", 10*time.Millisecond)
		cache.Set("valid", "value3", 1*time.Second)

		// Wait for some items to expire
		time.Sleep(20 * time.Millisecond)

		// Run cleanup
		cache.Cleanup()

		// Check expired items are removed
		_, found1 := cache.Get("expired1")
		_, found2 := cache.Get("expired2")
		_, found3 := cache.Get("valid")

		if found1 {
			t.Error("Expected expired1 to be cleaned up")
		}
		if found2 {
			t.Error("Expected expired2 to be cleaned up")
		}
		if !found3 {
			t.Error("Expected valid item to remain in cache")
		}
	})

	t.Run("Concurrent Access", func(t *testing.T) {
		cache := NewCache()
		done := make(chan bool)

		// Start multiple goroutines to access cache concurrently
		for i := 0; i < 10; i++ {
			go func(id int) {
				key := "key"
				value := "value"
				expiration := 1 * time.Second

				// Perform multiple operations
				cache.Set(key, value, expiration)
				cache.Get(key)
				cache.Delete(key)
				cache.Cleanup()

				done <- true
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("Zero Expiration", func(t *testing.T) {
		cache := NewCache()
		key := "test-key"
		value := "test-value"

		// Set with zero expiration
		cache.Set(key, value, 0)

		// Should not find the key
		_, found := cache.Get(key)
		if found {
			t.Error("Expected key with zero expiration to be immediately expired")
		}
	})

	t.Run("Negative Expiration", func(t *testing.T) {
		cache := NewCache()
		key := "test-key"
		value := "test-value"

		// Set with negative expiration
		cache.Set(key, value, -1*time.Second)

		// Should not find the key
		_, found := cache.Get(key)
		if found {
			t.Error("Expected key with negative expiration to be immediately expired")
		}
	})

	t.Run("Update Existing Key", func(t *testing.T) {
		cache := NewCache()
		key := "test-key"
		value1 := "value1"
		value2 := "value2"
		expiration := 1 * time.Second

		// Set initial value
		cache.Set(key, value1, expiration)

		// Update value
		cache.Set(key, value2, expiration)

		// Check updated value
		got, found := cache.Get(key)
		if !found {
			t.Error("Expected to find key in cache")
		}
		if got != value2 {
			t.Errorf("Expected updated value %v, got %v", value2, got)
		}
	})

	t.Run("Different Value Types", func(t *testing.T) {
		cache := NewCache()
		expiration := 1 * time.Second

		// Test with different value types
		testCases := []struct {
			key   string
			value interface{}
		}{
			{"string", "test"},
			{"int", 42},
			{"float", 3.14},
			{"bool", true},
			{"slice", []string{"a", "b", "c"}},
			{"map", map[string]int{"a": 1, "b": 2}},
			{"struct", struct{ Name string }{"test"}},
		}

		for _, tc := range testCases {
			t.Run(tc.key, func(t *testing.T) {
				cache.Set(tc.key, tc.value, expiration)
				got, found := cache.Get(tc.key)
				if !found {
					t.Error("Expected to find key in cache")
				}
				// Use reflect.DeepEqual for comparing complex types like slices and maps
				if !reflect.DeepEqual(got, tc.value) {
					t.Errorf("Expected value %v, got %v", tc.value, got)
				}
			})
		}
	})
}

func TestTokenCache(t *testing.T) {
	t.Run("Basic Operations", func(t *testing.T) {
		tc := NewTokenCache()
		token := "test-token"
		claims := map[string]interface{}{
			"sub":   "1234567890",
			"name":  "John Doe",
			"admin": true,
		}
		expiration := 1 * time.Second

		// Test Set and Get
		tc.Set(token, claims, expiration)
		gotClaims, found := tc.Get(token)
		if !found {
			t.Error("Expected to find token in cache")
		}
		if len(gotClaims) != len(claims) {
			t.Errorf("Expected %d claims, got %d", len(claims), len(gotClaims))
		}
		for k, v := range claims {
			if gotClaims[k] != v {
				t.Errorf("Expected claim %s to be %v, got %v", k, v, gotClaims[k])
			}
		}

		// Test Delete
		tc.Delete(token)
		_, found = tc.Get(token)
		if found {
			t.Error("Expected token to be deleted")
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		tc := NewTokenCache()
		token := "test-token"
		claims := map[string]interface{}{"sub": "1234567890"}
		expiration := 10 * time.Millisecond

		// Set with short expiration
		tc.Set(token, claims, expiration)

		// Wait for expiration
		time.Sleep(20 * time.Millisecond)

		// Should not find expired token
		_, found := tc.Get(token)
		if found {
			t.Error("Expected token to be expired")
		}
	})

	t.Run("Cleanup", func(t *testing.T) {
		tc := NewTokenCache()

		// Add multiple tokens with different expirations
		tc.Set("expired1", map[string]interface{}{"sub": "1"}, 10*time.Millisecond)
		tc.Set("expired2", map[string]interface{}{"sub": "2"}, 10*time.Millisecond)
		tc.Set("valid", map[string]interface{}{"sub": "3"}, 1*time.Second)

		// Wait for some tokens to expire
		time.Sleep(20 * time.Millisecond)

		// Run cleanup
		tc.Cleanup()

		// Check expired tokens are removed
		_, found1 := tc.Get("expired1")
		_, found2 := tc.Get("expired2")
		_, found3 := tc.Get("valid")

		if found1 {
			t.Error("Expected expired1 to be cleaned up")
		}
		if found2 {
			t.Error("Expected expired2 to be cleaned up")
		}
		if !found3 {
			t.Error("Expected valid token to remain in cache")
		}
	})

	t.Run("Token Prefix", func(t *testing.T) {
		tc := NewTokenCache()
		token := "test-token"
		claims := map[string]interface{}{"sub": "1234567890"}
		expiration := 1 * time.Second

		// Set token
		tc.Set(token, claims, expiration)

		// Verify internal storage uses prefix
		_, found := tc.cache.Get("t-" + token)
		if !found {
			t.Error("Expected to find prefixed token in underlying cache")
		}
	})
}
