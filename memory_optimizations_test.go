package traefikoidc

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestMemoryOptimizations(t *testing.T) {
	t.Run("buffer pool", func(t *testing.T) {
		pool := NewBufferPool(4096)

		// Get buffer
		buf := pool.Get()
		if buf == nil {
			t.Fatal("Expected non-nil buffer")
		}

		// Use buffer
		buf.WriteString("test data")
		if buf.String() != "test data" {
			t.Error("Buffer not working correctly")
		}

		// Return to pool
		pool.Put(buf)

		// Get again - should be clean
		buf2 := pool.Get()
		if buf2.Len() != 0 {
			t.Error("Expected clean buffer from pool")
		}
		pool.Put(buf2)
	})

	t.Run("large buffer not pooled", func(t *testing.T) {
		pool := NewBufferPool(1024)

		buf := pool.Get()
		// Grow buffer beyond limit
		buf.Write(make([]byte, 2048))

		capacity := buf.Cap()
		pool.Put(buf)

		// Get new buffer - should not be the large one
		buf2 := pool.Get()
		if buf2.Cap() == capacity && capacity > 1024 {
			t.Error("Large buffer should not be returned to pool")
		}
		pool.Put(buf2)
	})

	t.Run("gzip writer pool", func(t *testing.T) {
		pool := NewGzipWriterPool()

		w := pool.Get()
		if w == nil {
			t.Fatal("Expected non-nil gzip writer")
		}

		var buf bytes.Buffer
		w.Reset(&buf)
		w.Write([]byte("test data"))
		w.Close()

		if buf.Len() == 0 {
			t.Error("Gzip writer not working")
		}

		pool.Put(w)
	})

	t.Run("compress and decompress optimized", func(t *testing.T) {
		// Use larger data that will actually benefit from compression
		original := strings.Repeat("This is test data that should be compressed. ", 100)

		compressed, err := CompressTokenOptimized(original)
		if err != nil {
			t.Fatalf("Compression failed: %v", err)
		}

		// Check if it was actually compressed (should be for repetitive data)
		if len(compressed) >= len(original) {
			// If not compressed, it should return original
			if compressed != original {
				t.Error("Expected original data when compression doesn't help")
			}
			// Skip decompression test for uncompressed data
			return
		}

		decompressed, err := DecompressTokenOptimized(compressed)
		if err != nil {
			t.Fatalf("Decompression failed: %v", err)
		}

		if decompressed != original {
			t.Errorf("Decompressed data doesn't match: got %s, want %s",
				decompressed, original)
		}
	})

	t.Run("compression threshold", func(t *testing.T) {
		// Small data that won't benefit from compression
		small := "abc"
		compressed, _ := CompressTokenOptimized(small)

		// Should return original if compression doesn't help
		if compressed != small {
			t.Error("Small data should not be compressed")
		}

		// Large repetitive data that benefits from compression
		large := strings.Repeat("test", 1000)
		compressed, _ = CompressTokenOptimized(large)

		if len(compressed) >= len(large) {
			t.Error("Large repetitive data should be compressed")
		}
	})

	t.Run("singleton logger", func(t *testing.T) {
		opts := GetMemoryOptimizations()

		logger1 := opts.GetSingletonLogger("debug")
		logger2 := opts.GetSingletonLogger("info") // Different level, but should return same instance

		if logger1 != logger2 {
			t.Error("Expected same logger instance")
		}
	})

	t.Run("simplified session data", func(t *testing.T) {
		session := NewSimplifiedSessionData()

		// Set and get token
		session.SetToken("access", "token123")
		val, exists := session.GetToken("access")

		if !exists || val != "token123" {
			t.Error("Token not stored correctly")
		}

		// Clear
		session.Clear()
		_, exists = session.GetToken("access")
		if exists {
			t.Error("Token should be cleared")
		}
	})

	t.Run("concurrent pool usage", func(t *testing.T) {
		pool := NewBufferPool(4096)
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				buf := pool.Get()
				buf.WriteString("concurrent test")
				_ = buf.String()
				pool.Put(buf)
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent compression", func(t *testing.T) {
		var wg sync.WaitGroup
		// Use larger data that will actually compress
		data := strings.Repeat("test data for compression ", 100)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				compressed, err := CompressTokenOptimized(data)
				if err != nil {
					t.Errorf("Compression failed: %v", err)
					return
				}

				// Only try to decompress if it was actually compressed
				if len(compressed) < len(data) {
					decompressed, err := DecompressTokenOptimized(compressed)
					if err != nil {
						t.Errorf("Decompression failed: %v", err)
						return
					}

					if decompressed != data {
						t.Error("Data mismatch after compression/decompression")
					}
				} else {
					// Not compressed, should be same as original
					if compressed != data {
						t.Error("Uncompressed data doesn't match original")
					}
				}
			}()
		}

		wg.Wait()
	})
}

func BenchmarkMemoryOptimizations(b *testing.B) {
	data := strings.Repeat("benchmark test data ", 100)

	b.Run("CompressOptimized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = CompressTokenOptimized(data)
		}
	})

	b.Run("BufferPool", func(b *testing.B) {
		pool := NewBufferPool(4096)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			buf := pool.Get()
			buf.WriteString("test")
			pool.Put(buf)
		}
	})

	b.Run("NoPool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := bytes.NewBuffer(make([]byte, 0, 1024))
			buf.WriteString("test")
		}
	})
}
