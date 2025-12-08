package traefikoidc

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func BenchmarkMemoryLeakFixes(b *testing.B) {
	suite := NewMemoryLeakFixesTestSuite()

	b.Run("OptimizedCacheLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache := NewOptimizedCache()
			cache.Set("bench-key", "bench-value", time.Minute)
			_, _ = cache.Get("bench-key")
			cache.Close()
		}
	})

	b.Run("BackgroundTaskLifecycle", func(b *testing.B) {
		logger := GetSingletonNoOpLogger()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			taskFunc := func() {}
			task := NewBackgroundTask("bench-task", 100*time.Millisecond, taskFunc, logger)
			task.Start()
			task.Stop()
		}
	})

	b.Run("LazyBackgroundTaskLifecycle", func(b *testing.B) {
		logger := GetSingletonNoOpLogger()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			taskFunc := func() {}
			task := NewLazyBackgroundTask("bench-lazy-task", 100*time.Millisecond, taskFunc, logger)
			task.StartIfNeeded()
			task.Stop()
		}
	})

	b.Run("LazyCacheLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache := NewLazyCache()
			cache.Set("bench-key", "bench-value", time.Minute)
			_, _ = cache.Get("bench-key")
		}
	})

	b.Run("MetadataCacheLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			cache := NewMetadataCache(&wg)
			cache.Close()
		}
	})

	b.Run("SecureDataCleanup", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache := NewOptimizedCache()
			sensitiveData := []byte(suite.factory.GenerateRandomString(64))
			cache.Set("sensitive-key", sensitiveData, time.Minute)
			cache.Close()
		}
	})
}

func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("Cache_Operations", func(b *testing.B) {
		b.ReportAllocs()
		cache := NewCache()
		defer cache.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench-key-%d", i)
			cache.Set(key, "value", time.Minute)
			cache.Get(key)
			cache.Delete(key)
		}
	})

	b.Run("Session_Creation", func(b *testing.B) {
		b.ReportAllocs()
		sm, _ := NewSessionManager(
			"test-encryption-key-32-bytes-long-enough",
			false,
			"",
			"",
			0,
			NewLogger("error"),
		)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			_, _ = sm.GetSession(req)
		}
	})

	b.Run("Buffer_Pool", func(b *testing.B) {
		b.ReportAllocs()
		pool := NewBufferPool(4096)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := pool.Get()
			buf.WriteString("benchmark data")
			pool.Put(buf)
		}
	})

	b.Run("Gzip_Pool", func(b *testing.B) {
		b.ReportAllocs()
		pool := NewGzipWriterPool()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := pool.Get()
			var buf bytes.Buffer
			w.Reset(&buf)
			w.Write([]byte("benchmark compression data"))
			w.Close()
			pool.Put(w)
		}
	})

	b.Run("Plugin_Request", func(b *testing.B) {
		b.ReportAllocs()
		config := CreateConfig()
		config.ProviderURL = "https://accounts.google.com"
		config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler, _ := New(context.Background(), next, config, "bench")
		plugin := handler.(*TraefikOidc)
		defer plugin.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			plugin.ServeHTTP(w, req)
		}
	})
}
