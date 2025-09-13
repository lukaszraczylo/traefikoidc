package traefikoidc

import (
	"sync"
	"testing"
	"time"
)

func TestBoundedCache(t *testing.T) {
	t.Run("basic operations", func(t *testing.T) {
		cache := NewBoundedCache(10)
		defer cache.Close()

		// Set and get
		cache.Set("key1", "value1", time.Minute)
		val, found := cache.Get("key1")

		if !found {
			t.Error("Expected to find key1")
		}
		if val != "value1" {
			t.Errorf("Expected value1, got %v", val)
		}

		// Delete
		cache.Delete("key1")
		_, found = cache.Get("key1")
		if found {
			t.Error("Expected key1 to be deleted")
		}
	})

	t.Run("size limit enforcement", func(t *testing.T) {
		cache := NewBoundedCache(5)
		defer cache.Close()

		// Add items up to the limit
		for i := 0; i < 10; i++ {
			key := string(rune('a' + i))
			cache.Set(key, i, time.Minute)
		}

		// Cache should only have 5 items
		if cache.Size() > 5 {
			t.Errorf("Cache size %d exceeds limit of 5", cache.Size())
		}

		// Oldest items should be evicted
		_, found := cache.Get("a")
		if found {
			t.Error("Expected oldest item 'a' to be evicted")
		}

		// Newest items should still be present
		_, found = cache.Get("j")
		if !found {
			t.Error("Expected newest item 'j' to be present")
		}
	})

	t.Run("LRU eviction", func(t *testing.T) {
		cache := NewBoundedCache(3)
		defer cache.Close()

		// Add 3 items
		cache.Set("a", 1, time.Minute)
		cache.Set("b", 2, time.Minute)
		cache.Set("c", 3, time.Minute)

		// Access 'a' to make it recently used
		cache.Get("a")

		// Add new item, should evict 'b' (least recently used)
		cache.Set("d", 4, time.Minute)

		_, foundA := cache.Get("a")
		_, foundB := cache.Get("b")
		_, foundC := cache.Get("c")
		_, foundD := cache.Get("d")

		if !foundA {
			t.Error("Expected 'a' to be present (recently accessed)")
		}
		if foundB {
			t.Error("Expected 'b' to be evicted (LRU)")
		}
		if !foundC {
			t.Error("Expected 'c' to be present")
		}
		if !foundD {
			t.Error("Expected 'd' to be present (newest)")
		}
	})

	t.Run("expiration", func(t *testing.T) {
		cache := NewBoundedCache(10)
		defer cache.Close()

		// Set with short TTL
		cache.Set("expire", "value", 100*time.Millisecond)

		// Should exist initially
		_, found := cache.Get("expire")
		if !found {
			t.Error("Expected to find key before expiration")
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired
		_, found = cache.Get("expire")
		if found {
			t.Error("Expected key to be expired")
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		cache := NewBoundedCache(100)
		defer cache.Close()

		var wg sync.WaitGroup

		// Concurrent writes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := string(rune('a' + (id % 26)))
				cache.Set(key, id, time.Minute)
			}(i)
		}

		// Concurrent reads
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := string(rune('a' + (id % 26)))
				cache.Get(key)
			}(i)
		}

		wg.Wait()

		// Verify cache is still functional
		cache.Set("test", "value", time.Minute)
		val, found := cache.Get("test")
		if !found || val != "value" {
			t.Error("Cache not functional after concurrent access")
		}
	})

	t.Run("clear operation", func(t *testing.T) {
		cache := NewBoundedCache(10)
		defer cache.Close()

		// Add items
		for i := 0; i < 5; i++ {
			cache.Set(string(rune('a'+i)), i, time.Minute)
		}

		// Clear cache
		cache.Clear()

		if cache.Size() != 0 {
			t.Errorf("Expected size 0 after clear, got %d", cache.Size())
		}

		// Verify items are gone
		_, found := cache.Get("a")
		if found {
			t.Error("Expected cache to be empty after clear")
		}
	})

	t.Run("stats", func(t *testing.T) {
		cache := NewBoundedCache(10)
		defer cache.Close()

		// Add some items
		for i := 0; i < 5; i++ {
			cache.Set(string(rune('a'+i)), i, time.Minute)
		}

		stats := cache.GetStats()

		if stats["max_size"] != 10 {
			t.Errorf("Expected max_size 10, got %v", stats["max_size"])
		}

		if size, ok := stats["size"].(int64); !ok || size != 5 {
			t.Errorf("Expected size 5, got %v (type: %T)", stats["size"], stats["size"])
		}
	})
}

func TestBoundedCacheRaceConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping race condition test in short mode")
	}

	cache := NewBoundedCache(50)
	defer cache.Close()

	var wg sync.WaitGroup

	// Concurrent operations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := string(rune('a' + (id % 26)))

			// Mix of operations
			cache.Set(key, id, time.Second)
			cache.Get(key)
			if id%10 == 0 {
				cache.Delete(key)
			}
			if id%20 == 0 {
				cache.Clear()
			}
			cache.GetStats()
		}(i)
	}

	wg.Wait()
}

func BenchmarkBoundedCache(b *testing.B) {
	cache := NewBoundedCache(1000)
	defer cache.Close()

	b.Run("Set", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := string(rune(i % 1000))
			cache.Set(key, i, time.Minute)
		}
	})

	b.Run("Get", func(b *testing.B) {
		// Pre-populate
		for i := 0; i < 1000; i++ {
			cache.Set(string(rune(i)), i, time.Minute)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := string(rune(i % 1000))
			cache.Get(key)
		}
	})
}
