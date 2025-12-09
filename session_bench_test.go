package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// BenchmarkSessionCreation benchmarks session creation operations
func BenchmarkSessionCreation(b *testing.B) {
	framework := &SessionTestFramework{
		metrics:    &SessionTestMetrics{},
		testTokens: make(map[string]string),
		config: &SessionTestConfig{
			MaxChunkSize: 3900,
			MaxSessions:  1000,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		atomic.AddInt64(&framework.metrics.SessionsCreated, 1)
		atomic.AddInt64(&framework.metrics.SessionsDestroyed, 1)
	}

	b.ReportMetric(float64(framework.metrics.SessionsCreated)/float64(b.N), "sessions/op")
}

// BenchmarkTokenGeneration benchmarks token generation operations
func BenchmarkTokenGeneration(b *testing.B) {
	framework := NewSessionTestFramework(&testing.T{})
	defer framework.Cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		framework.generateTestToken("access", 3600)
	}

	b.ReportMetric(float64(framework.metrics.TokensGenerated)/float64(b.N), "tokens/op")
}

// BenchmarkTokenValidation benchmarks token validation operations
func BenchmarkTokenValidation(b *testing.B) {
	framework := NewSessionTestFramework(&testing.T{})
	defer framework.Cleanup()

	token := framework.generateTestToken("access", 3600)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			atomic.AddInt64(&framework.metrics.TokensValidated, 1)
		}
	}

	b.ReportMetric(float64(framework.metrics.TokensValidated)/float64(b.N), "validations/op")
}

// BenchmarkLargeTokenChunking benchmarks large token chunking operations
func BenchmarkLargeTokenChunking(b *testing.B) {
	framework := &SessionTestFramework{
		metrics:    &SessionTestMetrics{},
		testTokens: make(map[string]string),
		config: &SessionTestConfig{
			MaxChunkSize: 3900,
		},
	}

	// Generate test token once
	largeToken := strings.Repeat("A", 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunks := make([]string, 0)
		for j := 0; j < len(largeToken); j += framework.config.MaxChunkSize {
			end := j + framework.config.MaxChunkSize
			if end > len(largeToken) {
				end = len(largeToken)
			}
			chunks = append(chunks, largeToken[j:end])
			atomic.AddInt64(&framework.metrics.ChunksCreated, 1)
		}

		// Reconstruct
		_ = strings.Join(chunks, "")
		atomic.AddInt64(&framework.metrics.ChunksRetrieved, int64(len(chunks)))
	}

	b.ReportMetric(float64(framework.metrics.ChunksCreated)/float64(b.N), "chunks_created/op")
	b.ReportMetric(float64(framework.metrics.ChunksRetrieved)/float64(b.N), "chunks_retrieved/op")
}

// BenchmarkConcurrentSessionOperations benchmarks concurrent session operations
func BenchmarkConcurrentSessionOperations(b *testing.B) {
	framework := &SessionTestFramework{
		metrics:    &SessionTestMetrics{},
		testTokens: make(map[string]string),
		sessionIDs: make([]string, 0),
		config: &SessionTestConfig{
			MaxSessions: 10000,
		},
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create session
			atomic.AddInt64(&framework.metrics.SessionsCreated, 1)

			// Generate token
			token := make([]byte, 32)
			rand.Read(token)
			tokenStr := base64.RawURLEncoding.EncodeToString(token)
			atomic.AddInt64(&framework.metrics.TokensGenerated, 1)

			// Validate token
			if len(tokenStr) > 0 {
				atomic.AddInt64(&framework.metrics.TokensValidated, 1)
			}

			// Destroy session
			atomic.AddInt64(&framework.metrics.SessionsDestroyed, 1)
		}
	})

	b.ReportMetric(float64(framework.metrics.SessionsCreated)/float64(b.N), "sessions/op")
	b.ReportMetric(float64(framework.metrics.TokensGenerated)/float64(b.N), "tokens/op")
}

// BenchmarkSessionOperations provides performance benchmarks for session operations
func BenchmarkSessionOperations(b *testing.B) {
	testTokens := NewTestTokens()
	perfHelper := NewPerformanceTestHelper()

	logger := NewLogger("error") // Reduce logging for benchmarks
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		b.Fatalf("Failed to create session manager: %v", err)
	}

	b.Run("GetSession", func(b *testing.B) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			session, err := sm.GetSession(req)
			if err != nil {
				b.Fatalf("GetSession failed: %v", err)
			}
			session.ReturnToPool()
		}
	})

	b.Run("SetAccessToken", func(b *testing.B) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		session, _ := sm.GetSession(req)
		token := testTokens.GetValidTokenSet().AccessToken

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			perfHelper.Measure(func() {
				session.SetAccessToken(token)
			})
		}

		session.ReturnToPool()
		b.Logf("Average SetAccessToken time: %v", perfHelper.GetAverageTime())
	})

	b.Run("GetAccessToken", func(b *testing.B) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		session, _ := sm.GetSession(req)
		session.SetAccessToken(testTokens.GetValidTokenSet().AccessToken)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			perfHelper.Measure(func() {
				_ = session.GetAccessToken()
			})
		}

		session.ReturnToPool()
		b.Logf("Average GetAccessToken time: %v", perfHelper.GetAverageTime())
	})

	b.Run("TokenCompression", func(b *testing.B) {
		largeToken := testTokens.CreateLargeValidJWT(5000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			compressed := compressToken(largeToken)
			_ = decompressToken(compressed)
		}
	})
}
