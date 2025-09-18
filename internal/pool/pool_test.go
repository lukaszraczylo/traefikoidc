package pool

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// TestManager_Singleton tests that Get() returns the same instance
func TestManager_Singleton(t *testing.T) {
	manager1 := Get()
	manager2 := Get()

	if manager1 != manager2 {
		t.Error("Get() should return the same instance (singleton)")
	}

	if manager1 == nil {
		t.Error("Get() should not return nil")
	}
}

// TestManager_BufferPools tests buffer pool operations
func TestManager_BufferPools(t *testing.T) {
	manager := Get()

	tests := []struct {
		name     string
		sizeHint int
		expected int // expected capacity range
	}{
		{"small buffer", 512, 1024},
		{"medium buffer", 2048, 4096},
		{"large buffer", 6144, 8192},
		{"xl buffer", 12288, 16384},
		{"oversized buffer", 32768, 32768}, // Should create new buffer
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := manager.GetBuffer(test.sizeHint)
			if buf == nil {
				t.Error("GetBuffer should not return nil")
			}

			if buf.Cap() < test.sizeHint {
				t.Errorf("Buffer capacity %d is less than size hint %d", buf.Cap(), test.sizeHint)
			}

			// Write some data
			buf.WriteString("test data")
			if buf.String() != "test data" {
				t.Error("Buffer should contain written data")
			}

			// Return to pool
			manager.PutBuffer(buf)

			// Buffer should be reset when returned to pool
			buf2 := manager.GetBuffer(test.sizeHint)
			if buf2.Len() != 0 {
				t.Error("Buffer from pool should be reset")
			}
		})
	}
}

// TestManager_PutBuffer_Nil tests putting nil buffer
func TestManager_PutBuffer_Nil(t *testing.T) {
	manager := Get()
	// Should not panic
	manager.PutBuffer(nil)
}

// TestManager_PutBuffer_Oversized tests rejection of oversized buffers
func TestManager_PutBuffer_Oversized(t *testing.T) {
	manager := Get()
	manager.ResetStats()

	// Create oversized buffer
	buf := bytes.NewBuffer(make([]byte, 0, 40000))
	manager.PutBuffer(buf)

	stats := manager.GetStats()
	if stats.OversizedRejects == 0 {
		t.Error("Oversized buffer should be rejected")
	}
}

// TestManager_GzipPools tests gzip writer and reader pools
func TestManager_GzipPools(t *testing.T) {
	manager := Get()

	// Test gzip writer
	writer := manager.GetGzipWriter()
	if writer == nil {
		t.Error("GetGzipWriter should not return nil")
	}

	// Test that we can use it
	var buf bytes.Buffer
	writer.Reset(&buf)
	writer.Write([]byte("test data"))
	writer.Close()

	if buf.Len() == 0 {
		t.Error("Gzip writer should have written compressed data")
	}

	// Return to pool
	manager.PutGzipWriter(writer)

	// Test gzip reader
	reader := manager.GetGzipReader()
	// Reader might be nil from pool initially
	if reader != nil {
		manager.PutGzipReader(reader)
	}
}

// TestManager_GzipPools_Nil tests putting nil gzip objects
func TestManager_GzipPools_Nil(t *testing.T) {
	manager := Get()

	// Should not panic
	manager.PutGzipWriter(nil)
	manager.PutGzipReader(nil)
}

// TestManager_StringBuilderPool tests string builder pool
func TestManager_StringBuilderPool(t *testing.T) {
	manager := Get()

	sb := manager.GetStringBuilder()
	if sb == nil {
		t.Error("GetStringBuilder should not return nil")
	}

	// Should be reset
	if sb.Len() != 0 {
		t.Error("String builder from pool should be reset")
	}

	// Test writing
	sb.WriteString("test")
	sb.WriteString(" data")
	if sb.String() != "test data" {
		t.Error("String builder should contain written data")
	}

	// Return to pool
	manager.PutStringBuilder(sb)

	// Get another one - should be reset
	sb2 := manager.GetStringBuilder()
	if sb2.Len() != 0 {
		t.Error("String builder from pool should be reset")
	}
}

// TestManager_StringBuilderPool_Nil tests putting nil string builder
func TestManager_StringBuilderPool_Nil(t *testing.T) {
	manager := Get()
	// Should not panic
	manager.PutStringBuilder(nil)
}

// TestManager_StringBuilderPool_Oversized tests rejection of oversized string builders
func TestManager_StringBuilderPool_Oversized(t *testing.T) {
	manager := Get()
	manager.ResetStats()

	// Create oversized string builder
	sb := &strings.Builder{}
	sb.Grow(20000)
	sb.WriteString("test")

	manager.PutStringBuilder(sb)

	stats := manager.GetStats()
	if stats.OversizedRejects == 0 {
		t.Error("Oversized string builder should be rejected")
	}
}

// TestManager_JWTBufferPool tests JWT buffer pool
func TestManager_JWTBufferPool(t *testing.T) {
	manager := Get()

	jwtBuf := manager.GetJWTBuffer()
	if jwtBuf == nil {
		t.Error("GetJWTBuffer should not return nil")
		return
	}

	// Check structure
	if jwtBuf.Header == nil || jwtBuf.Payload == nil || jwtBuf.Signature == nil {
		t.Error("JWT buffer should have all fields initialized")
	}

	// Should be empty initially
	if len(jwtBuf.Header) != 0 || len(jwtBuf.Payload) != 0 || len(jwtBuf.Signature) != 0 {
		t.Error("JWT buffer from pool should be reset")
	}

	// Use the buffer
	jwtBuf.Header = append(jwtBuf.Header, []byte("header")...)
	jwtBuf.Payload = append(jwtBuf.Payload, []byte("payload")...)
	jwtBuf.Signature = append(jwtBuf.Signature, []byte("signature")...)

	// Return to pool
	manager.PutJWTBuffer(jwtBuf)

	// Get another one - should be reset
	jwtBuf2 := manager.GetJWTBuffer()
	if len(jwtBuf2.Header) != 0 || len(jwtBuf2.Payload) != 0 || len(jwtBuf2.Signature) != 0 {
		t.Error("JWT buffer from pool should be reset")
	}
}

// TestManager_JWTBufferPool_Nil tests putting nil JWT buffer
func TestManager_JWTBufferPool_Nil(t *testing.T) {
	manager := Get()
	// Should not panic
	manager.PutJWTBuffer(nil)
}

// TestManager_JWTBufferPool_Oversized tests rejection of oversized JWT buffers
func TestManager_JWTBufferPool_Oversized(t *testing.T) {
	manager := Get()
	manager.ResetStats()

	// Create oversized JWT buffer
	jwtBuf := &JWTBuffer{
		Header:    make([]byte, 0, 3000),  // Over 2048 limit
		Payload:   make([]byte, 0, 10000), // Over 8192 limit
		Signature: make([]byte, 0, 3000),  // Over 2048 limit
	}

	manager.PutJWTBuffer(jwtBuf)

	stats := manager.GetStats()
	if stats.OversizedRejects == 0 {
		t.Error("Oversized JWT buffer should be rejected")
	}
}

// TestManager_HTTPResponsePool tests HTTP response buffer pool
func TestManager_HTTPResponsePool(t *testing.T) {
	manager := Get()

	buf := manager.GetHTTPResponseBuffer()
	if buf == nil {
		t.Error("GetHTTPResponseBuffer should not return nil")
	}

	// Should be empty initially
	if len(buf) != 0 {
		t.Error("HTTP buffer from pool should be empty")
	}

	// Use the buffer
	buf = append(buf, []byte("HTTP response data")...)

	// Return to pool
	manager.PutHTTPResponseBuffer(buf)

	// Get another one - should be reset
	buf2 := manager.GetHTTPResponseBuffer()
	if len(buf2) != 0 {
		t.Error("HTTP buffer from pool should be reset")
	}
}

// TestManager_HTTPResponsePool_Nil tests putting nil HTTP buffer
func TestManager_HTTPResponsePool_Nil(t *testing.T) {
	manager := Get()
	// Should not panic
	manager.PutHTTPResponseBuffer(nil)
}

// TestManager_HTTPResponsePool_Oversized tests rejection of oversized HTTP buffers
func TestManager_HTTPResponsePool_Oversized(t *testing.T) {
	manager := Get()
	manager.ResetStats()

	// Create oversized buffer
	buf := make([]byte, 0, 40000)
	manager.PutHTTPResponseBuffer(buf)

	stats := manager.GetStats()
	if stats.OversizedRejects == 0 {
		t.Error("Oversized HTTP buffer should be rejected")
	}
}

// TestManager_ByteSlicePool tests byte slice pool with dynamic sizing
func TestManager_ByteSlicePool(t *testing.T) {
	manager := Get()

	tests := []int{256, 512, 1024, 2048, 4096, 8192, 16384}

	for _, size := range tests {
		t.Run(strings.Join([]string{"size", string(rune(size))}, "_"), func(t *testing.T) {
			slice := manager.GetByteSlice(size)
			if slice == nil {
				t.Error("GetByteSlice should not return nil")
			}

			if len(slice) != size {
				t.Errorf("Byte slice length %d != requested size %d", len(slice), size)
			}

			if cap(slice) < size {
				t.Errorf("Byte slice capacity %d < requested size %d", cap(slice), size)
			}

			// Use the slice
			copy(slice, []byte("test data"))

			// Return to pool
			manager.PutByteSlice(slice)
		})
	}
}

// TestManager_ByteSlicePool_CustomSize tests byte slice pool with non-standard sizes
func TestManager_ByteSlicePool_CustomSize(t *testing.T) {
	manager := Get()

	// Test custom size (should round up to power of 2)
	slice := manager.GetByteSlice(300)
	if slice == nil {
		t.Error("GetByteSlice should not return nil")
	}

	if len(slice) != 300 {
		t.Errorf("Byte slice length %d != requested size 300", len(slice))
	}

	// Capacity should be >= 300 (likely 512 as next power of 2)
	if cap(slice) < 300 {
		t.Error("Byte slice capacity should be at least 300")
	}

	manager.PutByteSlice(slice)
}

// TestManager_ByteSlicePool_Nil tests putting nil byte slice
func TestManager_ByteSlicePool_Nil(t *testing.T) {
	manager := Get()
	// Should not panic
	manager.PutByteSlice(nil)
}

// TestManager_ByteSlicePool_Oversized tests rejection of oversized byte slices
func TestManager_ByteSlicePool_Oversized(t *testing.T) {
	manager := Get()

	// Create oversized slice
	slice := make([]byte, 100000)

	// Should not panic and should not be pooled
	manager.PutByteSlice(slice)
}

// TestManager_Stats tests statistics tracking
func TestManager_Stats(t *testing.T) {
	manager := Get()
	manager.ResetStats()

	initialStats := manager.GetStats()
	if initialStats.BufferGets != 0 || initialStats.BufferPuts != 0 {
		t.Error("Stats should be zero after reset")
	}

	// Perform operations
	buf := manager.GetBuffer(1024)
	manager.PutBuffer(buf)

	writer := manager.GetGzipWriter()
	manager.PutGzipWriter(writer)

	sb := manager.GetStringBuilder()
	manager.PutStringBuilder(sb)

	jwtBuf := manager.GetJWTBuffer()
	manager.PutJWTBuffer(jwtBuf)

	httpBuf := manager.GetHTTPResponseBuffer()
	manager.PutHTTPResponseBuffer(httpBuf)

	// Check stats
	stats := manager.GetStats()
	if stats.BufferGets == 0 || stats.BufferPuts == 0 {
		t.Error("Buffer stats should be incremented")
	}
	if stats.GzipGets == 0 || stats.GzipPuts == 0 {
		t.Error("Gzip stats should be incremented")
	}
	if stats.StringGets == 0 || stats.StringPuts == 0 {
		t.Error("String stats should be incremented")
	}
	if stats.JWTGets == 0 || stats.JWTPuts == 0 {
		t.Error("JWT stats should be incremented")
	}
	if stats.HTTPGets == 0 || stats.HTTPPuts == 0 {
		t.Error("HTTP stats should be incremented")
	}
}

// TestManager_ResetStats tests statistics reset
func TestManager_ResetStats(t *testing.T) {
	manager := Get()

	// Perform some operations
	buf := manager.GetBuffer(1024)
	manager.PutBuffer(buf)

	// Check that stats are non-zero
	stats := manager.GetStats()
	if stats.BufferGets == 0 {
		t.Error("Stats should be non-zero before reset")
	}

	// Reset stats
	manager.ResetStats()

	// Check that stats are zero
	resetStats := manager.GetStats()
	if resetStats.BufferGets != 0 || resetStats.BufferPuts != 0 {
		t.Error("Stats should be zero after reset")
	}
}

// TestManager_ConcurrentAccess tests concurrent access to pools
func TestManager_ConcurrentAccess(t *testing.T) {
	manager := Get()
	manager.ResetStats()

	var wg sync.WaitGroup
	numGoroutines := 50
	operationsPerGoroutine := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				// Test buffer pool
				buf := manager.GetBuffer(1024)
				buf.WriteString("test")
				manager.PutBuffer(buf)

				// Test string builder pool
				sb := manager.GetStringBuilder()
				sb.WriteString("test")
				manager.PutStringBuilder(sb)

				// Test JWT buffer pool
				jwtBuf := manager.GetJWTBuffer()
				jwtBuf.Header = append(jwtBuf.Header, byte(j))
				manager.PutJWTBuffer(jwtBuf)

				// Test byte slice pool
				slice := manager.GetByteSlice(256)
				slice[0] = byte(j)
				manager.PutByteSlice(slice)
			}
		}()
	}

	wg.Wait()

	// Check that operations completed without panic
	stats := manager.GetStats()
	expectedOps := uint64(numGoroutines * operationsPerGoroutine)
	if stats.BufferGets < expectedOps || stats.StringGets < expectedOps || stats.JWTGets < expectedOps {
		t.Error("Some operations may have failed during concurrent access")
	}
}

// TestGlobalConvenienceFunctions tests the global convenience functions
func TestGlobalConvenienceFunctions(t *testing.T) {
	// Test buffer functions
	buf := Buffer(1024)
	if buf == nil {
		t.Error("Buffer() should not return nil")
	}
	buf.WriteString("test")
	ReturnBuffer(buf)

	// Test gzip functions
	writer := GzipWriter()
	if writer == nil {
		t.Error("GzipWriter() should not return nil")
	}
	ReturnGzipWriter(writer)

	// Test string builder functions
	sb := StringBuilder()
	if sb == nil {
		t.Error("StringBuilder() should not return nil")
	}
	sb.WriteString("test")
	ReturnStringBuilder(sb)

	// Test JWT buffer functions
	jwtBuf := JWTBuffers()
	if jwtBuf == nil {
		t.Error("JWTBuffers() should not return nil")
	}
	ReturnJWTBuffers(jwtBuf)

	// Test HTTP buffer functions
	httpBuf := HTTPBuffer()
	if httpBuf == nil {
		t.Error("HTTPBuffer() should not return nil")
	}
	ReturnHTTPBuffer(httpBuf)

	// Test byte slice functions
	slice := ByteSlice(256)
	if slice == nil {
		t.Error("ByteSlice() should not return nil")
	}
	if len(slice) != 256 {
		t.Error("ByteSlice() should return correct size")
	}
	ReturnByteSlice(slice)
}

// Benchmark tests for performance verification
func BenchmarkManager_GetBuffer(b *testing.B) {
	manager := Get()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := manager.GetBuffer(1024)
		manager.PutBuffer(buf)
	}
}

func BenchmarkManager_GetStringBuilder(b *testing.B) {
	manager := Get()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sb := manager.GetStringBuilder()
		manager.PutStringBuilder(sb)
	}
}

func BenchmarkManager_GetJWTBuffer(b *testing.B) {
	manager := Get()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		jwtBuf := manager.GetJWTBuffer()
		manager.PutJWTBuffer(jwtBuf)
	}
}

func BenchmarkManager_GetByteSlice(b *testing.B) {
	manager := Get()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		slice := manager.GetByteSlice(1024)
		manager.PutByteSlice(slice)
	}
}

func BenchmarkManager_ConcurrentAccess(b *testing.B) {
	manager := Get()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := manager.GetBuffer(1024)
			buf.WriteString("test")
			manager.PutBuffer(buf)
		}
	})
}
