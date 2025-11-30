package backends

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// setupBenchmarkRedis creates a miniredis instance for benchmarking
func setupBenchmarkRedis(b *testing.B) string {
	b.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		mr.Close()
	})
	return mr.Addr()
}

// BenchmarkRedisOperations_WithPooling benchmarks memory allocations with object pooling
func BenchmarkRedisOperations_WithPooling(b *testing.B) {
	addr := setupBenchmarkRedis(b)

	config := &PoolConfig{
		Address:        addr,
		MaxConnections: 10,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			b.Fatal(err)
		}

		// Perform various operations
		_, _ = conn.Do("SET", "bench-key", "bench-value")
		_, _ = conn.Do("GET", "bench-key")
		_, _ = conn.Do("EXISTS", "bench-key")
		_, _ = conn.Do("DEL", "bench-key")

		pool.Put(conn)
	}
}

// BenchmarkRedisBackend_SetGet benchmarks the full backend with pooling
func BenchmarkRedisBackend_SetGet(b *testing.B) {
	addr := setupBenchmarkRedis(b)

	backend, err := NewRedisBackend(&Config{
		RedisAddr: addr,
		PoolSize:  10,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()

	ctx := context.Background()
	testData := []byte("benchmark test data with some content")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Set operation
		err := backend.Set(ctx, "bench-key", testData, 0)
		if err != nil {
			b.Fatal(err)
		}

		// Get operation
		_, _, _, err = backend.Get(ctx, "bench-key")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRedisBackend_ConcurrentAccess benchmarks concurrent operations with pooling
func BenchmarkRedisBackend_ConcurrentAccess(b *testing.B) {
	addr := setupBenchmarkRedis(b)

	backend, err := NewRedisBackend(&Config{
		RedisAddr: addr,
		PoolSize:  10,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()

	ctx := context.Background()
	testData := []byte("concurrent benchmark data")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = backend.Set(ctx, "concurrent-key", testData, 0)
			_, _, _, _ = backend.Get(ctx, "concurrent-key")
		}
	})
}

// BenchmarkRESPProtocol_WriteRead benchmarks RESP protocol encoding/decoding
func BenchmarkRESPProtocol_WriteRead(b *testing.B) {
	addr := setupBenchmarkRedis(b)

	config := &PoolConfig{
		Address:        addr,
		MaxConnections: 10,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Get(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Put(conn)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// This tests the pooling of RESPReader/RESPWriter
		_, _ = conn.Do("PING")
	}
}

// BenchmarkConnectionPool_GetPut benchmarks connection pool operations
func BenchmarkConnectionPool_GetPut(b *testing.B) {
	addr := setupBenchmarkRedis(b)

	config := &PoolConfig{
		Address:        addr,
		MaxConnections: 10,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			b.Fatal(err)
		}
		pool.Put(conn)
	}
}
