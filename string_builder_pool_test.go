package traefikoidc

import (
	"strings"
	"sync"
	"testing"
)

func TestStringBuilderPool(t *testing.T) {
	t.Run("basic get and put", func(t *testing.T) {
		pool := GetGlobalStringBuilderPool()

		sb := pool.Get()
		if sb == nil {
			t.Fatal("Expected non-nil string builder")
		}

		sb.WriteString("test")
		result := sb.String()

		if result != "test" {
			t.Errorf("Expected 'test', got '%s'", result)
		}

		pool.Put(sb)

		// Get again should return clean builder
		sb2 := pool.Get()
		if sb2.Len() != 0 {
			t.Error("Expected clean string builder after get")
		}
		pool.Put(sb2)
	})

	t.Run("format string", func(t *testing.T) {
		pool := GetGlobalStringBuilderPool()

		result := pool.FormatString(func(sb *strings.Builder) {
			sb.WriteString("hello")
			sb.WriteRune(' ')
			sb.WriteString("world")
		})

		if result != "hello world" {
			t.Errorf("Expected 'hello world', got '%s'", result)
		}
	})

	t.Run("build session name", func(t *testing.T) {
		tests := []struct {
			base     string
			index    int
			expected string
		}{
			{"session", 0, "session_0"},
			{"token", 5, "token_5"},
			{"chunk", 15, "chunk_15"},
			{"data", 99, "data_99"},
		}

		for _, tt := range tests {
			result := BuildSessionName(tt.base, tt.index)
			if result != tt.expected {
				t.Errorf("BuildSessionName(%s, %d) = %s, want %s",
					tt.base, tt.index, result, tt.expected)
			}
		}
	})

	t.Run("build cache key", func(t *testing.T) {
		tests := []struct {
			parts    []string
			expected string
		}{
			{[]string{"user", "123"}, "user:123"},
			{[]string{"token", "abc", "def"}, "token:abc:def"},
			{[]string{"single"}, "single"},
			{[]string{}, ""},
		}

		for _, tt := range tests {
			result := BuildCacheKey(tt.parts...)
			if result != tt.expected {
				t.Errorf("BuildCacheKey(%v) = %s, want %s",
					tt.parts, result, tt.expected)
			}
		}
	})

	t.Run("concurrent usage", func(t *testing.T) {
		pool := GetGlobalStringBuilderPool()
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Get and use builder
				sb := pool.Get()
				sb.WriteString("test")
				sb.WriteString(sbIntToString(id))
				_ = sb.String()
				pool.Put(sb)

				// Use FormatString
				_ = pool.FormatString(func(sb *strings.Builder) {
					sb.WriteString("format")
					sb.WriteString(sbIntToString(id))
				})

				// Use helper functions
				_ = BuildSessionName("concurrent", id)
				_ = BuildCacheKey("key", sbIntToString(id))
			}(i)
		}

		wg.Wait()
	})

	t.Run("large buffer not pooled", func(t *testing.T) {
		pool := GetGlobalStringBuilderPool()

		sb := pool.Get()
		// Create a large string
		for i := 0; i < 1000; i++ {
			sb.WriteString("large content ")
		}

		capacity := sb.Cap()
		pool.Put(sb)

		// Get new builder - should not be the large one
		sb2 := pool.Get()
		if sb2.Cap() == capacity && capacity > 4096 {
			t.Error("Large buffer should not be returned to pool")
		}
		pool.Put(sb2)
	})

	t.Run("sbIntToString", func(t *testing.T) {
		tests := []struct {
			n        int
			expected string
		}{
			{0, "0"},
			{5, "5"},
			{10, "10"},
			{99, "99"},
			{100, "100"},
			{-5, "-5"},
			{-99, "-99"},
		}

		for _, tt := range tests {
			result := sbIntToString(tt.n)
			if result != tt.expected {
				t.Errorf("sbIntToString(%d) = %s, want %s",
					tt.n, result, tt.expected)
			}
		}
	})
}

func BenchmarkStringOperations(b *testing.B) {
	b.Run("BuildSessionName_Pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = BuildSessionName("session", i%100)
		}
	})

	b.Run("BuildSessionName_Sprintf", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = "session_" + sbIntToString(i%100)
		}
	})

	b.Run("BuildCacheKey_Pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = BuildCacheKey("user", "token", "data")
		}
	})

	b.Run("BuildCacheKey_Concat", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = "user" + ":" + "token" + ":" + "data"
		}
	})
}
