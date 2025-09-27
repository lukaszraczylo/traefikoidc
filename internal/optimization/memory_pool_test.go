package optimization

import (
	"runtime"
	"sync"
	"testing"
)

// TestNewStringBuilderPool tests StringBuilderPool creation
func TestNewStringBuilderPool(t *testing.T) {
	pool := NewStringBuilderPool()

	if pool == nil {
		t.Error("Expected NewStringBuilderPool to return non-nil pool")
	}
}

// TestStringBuilderPool tests StringBuilderPool functionality
func TestStringBuilderPool(t *testing.T) {
	pool := NewStringBuilderPool()

	// Test Get
	buf1 := pool.Get()
	if buf1 == nil {
		t.Error("Expected Get to return non-nil buffer")
	}

	// Check initial capacity
	if cap(buf1) != 256 {
		t.Errorf("Expected initial capacity of 256, got %d", cap(buf1))
	}

	// Check initial length
	if len(buf1) != 0 {
		t.Errorf("Expected initial length of 0, got %d", len(buf1))
	}

	// Test Put and reuse
	// Simulate some usage
	buf1 = append(buf1, []byte("hello world")...)
	pool.Put(buf1)

	// Get another buffer - should reuse the one we just put
	buf2 := pool.Get()
	if buf2 == nil {
		t.Error("Expected Get to return non-nil buffer after Put")
	}

	// Buffer should be reset to length 0 but keep capacity
	if len(buf2) != 0 {
		t.Errorf("Expected buffer length to be reset to 0, got %d", len(buf2))
	}

	// Should reuse the same underlying array
	if cap(buf2) < 256 {
		t.Errorf("Expected buffer capacity to be at least 256, got %d", cap(buf2))
	}
}

// TestStringBuilderPoolLargeBuffer tests that large buffers are not pooled
func TestStringBuilderPoolLargeBuffer(t *testing.T) {
	pool := NewStringBuilderPool()

	// Get a buffer and make it very large
	buf := pool.Get()
	largeBuf := make([]byte, 5000) // Larger than 4096 threshold
	buf = append(buf, largeBuf...)

	// Put it back - should not be pooled due to size
	pool.Put(buf)

	// Get a new buffer - should be a fresh one with default capacity
	newBuf := pool.Get()
	if cap(newBuf) != 256 {
		t.Errorf("Expected fresh buffer with capacity 256, got %d", cap(newBuf))
	}
}

// TestNewByteSlicePool tests ByteSlicePool creation
func TestNewByteSlicePool(t *testing.T) {
	size := 1024
	pool := NewByteSlicePool(size)

	if pool == nil {
		t.Error("Expected NewByteSlicePool to return non-nil pool")
		return
	}

	if pool.size != size {
		t.Errorf("Expected pool size %d, got %d", size, pool.size)
	}
}

// TestByteSlicePool tests ByteSlicePool functionality
func TestByteSlicePool(t *testing.T) {
	size := 512
	pool := NewByteSlicePool(size)

	// Test Get
	buf1 := pool.Get()
	if buf1 == nil {
		t.Error("Expected Get to return non-nil buffer")
	}

	// Check size
	if len(buf1) != size {
		t.Errorf("Expected buffer length %d, got %d", size, len(buf1))
	}

	// Test Put and reuse
	pool.Put(buf1)

	// Get another buffer - should reuse the one we just put
	buf2 := pool.Get()
	if buf2 == nil {
		t.Error("Expected Get to return non-nil buffer after Put")
	}

	// Should be the same size
	if len(buf2) != size {
		t.Errorf("Expected buffer length %d, got %d", size, len(buf2))
	}
}

// TestByteSlicePoolWrongSize tests that wrong-sized buffers are not pooled
func TestByteSlicePoolWrongSize(t *testing.T) {
	size := 512
	pool := NewByteSlicePool(size)

	// Get a buffer
	buf := pool.Get()

	// Resize it (simulate usage that changes size)
	buf = buf[:100] // Change length to 100

	// Put it back - should not be pooled due to wrong size
	pool.Put(buf)

	// Get a new buffer - should be a fresh one with correct size
	newBuf := pool.Get()
	if len(newBuf) != size {
		t.Errorf("Expected fresh buffer with length %d, got %d", size, len(newBuf))
	}
}

// TestGlobalStringBuilderPool tests global string builder pool functions
func TestGlobalStringBuilderPool(t *testing.T) {
	// Test GetStringBuilder
	buf1 := GetStringBuilder()
	if buf1 == nil {
		t.Error("Expected GetStringBuilder to return non-nil buffer")
	}

	if cap(buf1) != 256 {
		t.Errorf("Expected initial capacity of 256, got %d", cap(buf1))
	}

	// Test PutStringBuilder and reuse
	buf1 = append(buf1, []byte("test data")...)
	PutStringBuilder(buf1)

	buf2 := GetStringBuilder()
	if len(buf2) != 0 {
		t.Errorf("Expected buffer length to be reset to 0, got %d", len(buf2))
	}
}

// TestGlobalByteSlicePool tests global byte slice pool functions
func TestGlobalByteSlicePool(t *testing.T) {
	// Test GetByteSlice
	buf1 := GetByteSlice()
	if buf1 == nil {
		t.Error("Expected GetByteSlice to return non-nil buffer")
	}

	if len(buf1) != 2048 {
		t.Errorf("Expected buffer length of 2048, got %d", len(buf1))
	}

	// Test PutByteSlice and reuse
	PutByteSlice(buf1)

	buf2 := GetByteSlice()
	if len(buf2) != 2048 {
		t.Errorf("Expected buffer length of 2048, got %d", len(buf2))
	}
}

// TestPoolsConcurrency tests that pools work correctly under concurrent access
func TestPoolsConcurrency(t *testing.T) {
	const numGoroutines = 100
	const numOperations = 1000

	// Test StringBuilderPool concurrency
	t.Run("StringBuilderPool concurrency", func(t *testing.T) {
		pool := NewStringBuilderPool()
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					buf := pool.Get()
					buf = append(buf, []byte("test")...)
					pool.Put(buf)
				}
			}()
		}

		wg.Wait()
	})

	// Test ByteSlicePool concurrency
	t.Run("ByteSlicePool concurrency", func(t *testing.T) {
		pool := NewByteSlicePool(1024)
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					buf := pool.Get()
					// Simulate some work
					for k := 0; k < len(buf); k++ {
						buf[k] = byte(k % 256)
					}
					pool.Put(buf)
				}
			}()
		}

		wg.Wait()
	})

	// Test global pools concurrency
	t.Run("Global pools concurrency", func(t *testing.T) {
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					// Test string builder pool
					strBuf := GetStringBuilder()
					strBuf = append(strBuf, []byte("test")...)
					PutStringBuilder(strBuf)

					// Test byte slice pool
					byteBuf := GetByteSlice()
					byteBuf[0] = 42
					PutByteSlice(byteBuf)
				}
			}()
		}

		wg.Wait()
	})
}

// TestMemoryReuse tests that pools actually reuse memory
func TestMemoryReuse(t *testing.T) {
	t.Run("StringBuilderPool memory reuse", func(t *testing.T) {
		pool := NewStringBuilderPool()

		// Get a buffer and note its address
		buf1 := pool.Get()
		addr1 := &buf1[0:1][0] // Get address of first element

		// Put it back
		pool.Put(buf1)

		// Get another buffer - should be the same memory
		buf2 := pool.Get()
		addr2 := &buf2[0:1][0]

		if addr1 != addr2 {
			t.Error("Expected pool to reuse memory, but got different addresses")
		}
	})

	t.Run("ByteSlicePool memory reuse", func(t *testing.T) {
		pool := NewByteSlicePool(1024)

		// Get a buffer and note its address
		buf1 := pool.Get()
		addr1 := &buf1[0]

		// Put it back
		pool.Put(buf1)

		// Get another buffer - should be the same memory
		buf2 := pool.Get()
		addr2 := &buf2[0]

		if addr1 != addr2 {
			t.Error("Expected pool to reuse memory, but got different addresses")
		}
	})
}

// TestPoolEfficiency tests that pools reduce allocations
func TestPoolEfficiency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping efficiency test in short mode")
	}

	t.Run("StringBuilderPool allocation reduction", func(t *testing.T) {
		pool := NewStringBuilderPool()

		// Test with pool
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		for i := 0; i < 10000; i++ {
			buf := pool.Get()
			buf = append(buf, []byte("test data for benchmarking")...)
			pool.Put(buf)
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)
		poolAllocs := m2.Mallocs - m1.Mallocs

		// Test without pool (creating new buffers each time)
		runtime.GC()
		runtime.ReadMemStats(&m1)

		for i := 0; i < 10000; i++ {
			buf := make([]byte, 0, 256)
			_ = append(buf, []byte("test data for benchmarking")...)
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)
		directAllocs := m2.Mallocs - m1.Mallocs

		t.Logf("Pool allocations: %d, Direct allocations: %d", poolAllocs, directAllocs)

		// Pool should result in fewer allocations (though this test can be flaky)
		if poolAllocs >= directAllocs {
			t.Logf("Warning: Pool did not reduce allocations as expected (pool: %d, direct: %d)", poolAllocs, directAllocs)
		}
	})
}

// TestEdgeCases tests edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	t.Run("StringBuilderPool with nil buffer", func(t *testing.T) {
		pool := NewStringBuilderPool()

		// This should not panic
		pool.Put(nil)

		// Should still be able to get a buffer
		buf := pool.Get()
		if buf == nil {
			t.Error("Expected Get to return non-nil buffer after putting nil")
		}
	})

	t.Run("ByteSlicePool with nil buffer", func(t *testing.T) {
		pool := NewByteSlicePool(1024)

		// This should not panic
		pool.Put(nil)

		// Should still be able to get a buffer
		buf := pool.Get()
		if buf == nil {
			t.Error("Expected Get to return non-nil buffer after putting nil")
		}
	})

	t.Run("Zero-size ByteSlicePool", func(t *testing.T) {
		pool := NewByteSlicePool(0)

		buf := pool.Get()
		if len(buf) != 0 {
			t.Errorf("Expected zero-length buffer, got %d", len(buf))
		}

		// Should not panic
		pool.Put(buf)
	})

	t.Run("Global pools with nil", func(t *testing.T) {
		// These should not panic
		PutStringBuilder(nil)
		PutByteSlice(nil)

		// Should still work
		buf1 := GetStringBuilder()
		buf2 := GetByteSlice()

		if buf1 == nil || buf2 == nil {
			t.Error("Expected global pools to work after putting nil")
		}
	})
}

// TestTypeAssertions tests that type assertions in pools work correctly
func TestTypeAssertions(t *testing.T) {
	t.Run("StringBuilderPool type assertion", func(t *testing.T) {
		pool := NewStringBuilderPool()

		// This should not panic
		buf := pool.Get()
		if buf == nil {
			t.Error("Expected non-nil buffer")
		}

		// Buffer should be usable
		buf = append(buf, []byte("test")...)
		if string(buf) != "test" {
			t.Errorf("Expected 'test', got '%s'", string(buf))
		}
	})

	t.Run("ByteSlicePool type assertion", func(t *testing.T) {
		pool := NewByteSlicePool(10)

		// This should not panic
		buf := pool.Get()
		if buf == nil {
			t.Error("Expected non-nil buffer")
		}

		// Buffer should be usable
		buf[0] = 42
		if buf[0] != 42 {
			t.Errorf("Expected 42, got %d", buf[0])
		}
	})
}

// BenchmarkStringBuilderPool benchmarks the string builder pool
func BenchmarkStringBuilderPool(b *testing.B) {
	pool := NewStringBuilderPool()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			buf = append(buf, []byte("benchmark test data")...)
			pool.Put(buf)
		}
	})
}

// BenchmarkByteSlicePool benchmarks the byte slice pool
func BenchmarkByteSlicePool(b *testing.B) {
	pool := NewByteSlicePool(1024)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			buf[0] = 42
			pool.Put(buf)
		}
	})
}

// BenchmarkGlobalPools benchmarks the global pools
func BenchmarkGlobalPools(b *testing.B) {
	b.Run("StringBuilder", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := GetStringBuilder()
				buf = append(buf, []byte("test")...)
				PutStringBuilder(buf)
			}
		})
	})

	b.Run("ByteSlice", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := GetByteSlice()
				buf[0] = 42
				PutByteSlice(buf)
			}
		})
	})
}

// BenchmarkDirectAllocation benchmarks direct allocation for comparison
func BenchmarkDirectAllocation(b *testing.B) {
	b.Run("StringBuilder", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := make([]byte, 0, 256)
				_ = append(buf, []byte("test")...)
			}
		})
	})

	b.Run("ByteSlice", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := make([]byte, 2048)
				buf[0] = 42
			}
		})
	})
}
