package traefikoidc

import (
	"testing"
	"time"
)

func TestPerformanceMetrics(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)

	t.Run("Record cache operations", func(t *testing.T) {
		metrics.RecordCacheHit()
		metrics.RecordCacheMiss()
		metrics.RecordCacheEviction()
		metrics.UpdateCacheSize(100)

		result := metrics.GetMetrics()

		if result["cache_hits"].(int64) != 1 {
			t.Errorf("Expected 1 cache hit, got %v", result["cache_hits"])
		}
		if result["cache_misses"].(int64) != 1 {
			t.Errorf("Expected 1 cache miss, got %v", result["cache_misses"])
		}
		if result["cache_evictions"].(int64) != 1 {
			t.Errorf("Expected 1 cache eviction, got %v", result["cache_evictions"])
		}
		if result["cache_size"].(int64) != 100 {
			t.Errorf("Expected cache size 100, got %v", result["cache_size"])
		}
	})

	t.Run("Record token operations", func(t *testing.T) {
		start := time.Now()
		time.Sleep(10 * time.Millisecond)
		metrics.RecordTokenVerification(time.Since(start), true)

		start = time.Now()
		time.Sleep(5 * time.Millisecond)
		metrics.RecordTokenValidation(time.Since(start), false)

		start = time.Now()
		time.Sleep(15 * time.Millisecond)
		metrics.RecordTokenRefresh(time.Since(start), true)

		result := metrics.GetMetrics()

		if result["token_verifications"].(int64) != 1 {
			t.Errorf("Expected 1 token verification, got %v", result["token_verifications"])
		}
		if result["token_validations"].(int64) != 1 {
			t.Errorf("Expected 1 token validation, got %v", result["token_validations"])
		}
		if result["token_refreshes"].(int64) != 1 {
			t.Errorf("Expected 1 token refresh, got %v", result["token_refreshes"])
		}
		if result["successful_verifications"].(int64) != 1 {
			t.Errorf("Expected 1 successful verification, got %v", result["successful_verifications"])
		}
		if result["failed_validations"].(int64) != 1 {
			t.Errorf("Expected 1 failed validation, got %v", result["failed_validations"])
		}
	})

	t.Run("Record rate limiting and sessions", func(t *testing.T) {
		metrics.RecordRateLimitedRequest()
		metrics.RecordSessionCreation()
		metrics.RecordSessionDeletion()

		result := metrics.GetMetrics()

		if result["rate_limited_requests"].(int64) != 1 {
			t.Errorf("Expected 1 rate limited request, got %v", result["rate_limited_requests"])
		}
		if result["sessions_created"].(int64) != 1 {
			t.Errorf("Expected 1 session created, got %v", result["sessions_created"])
		}
		if result["sessions_deleted"].(int64) != 1 {
			t.Errorf("Expected 1 session deleted, got %v", result["sessions_deleted"])
		}
	})

	t.Run("Get detailed timing metrics", func(t *testing.T) {
		// Add more timing data
		for i := 0; i < 5; i++ {
			metrics.RecordTokenVerification(time.Duration(i+1)*time.Millisecond, true)
		}

		detailed := metrics.GetDetailedTimingMetrics()

		if detailed["verification_stats"] == nil {
			t.Error("Expected verification stats to be present")
		}

		verificationStats := detailed["verification_stats"].(map[string]interface{})
		if verificationStats["count"].(int) != 6 { // 1 from previous test + 5 new
			t.Errorf("Expected 6 verifications, got %v", verificationStats["count"])
		}
	})
}

func TestResourceMonitor(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)
	monitor := NewResourceMonitor(metrics, logger)

	t.Run("Set limits", func(t *testing.T) {
		monitor.SetMemoryLimit(100 * 1024 * 1024) // 100MB
		monitor.SetCacheLimit(1000)
		monitor.SetSessionLimit(500)

		// Should not panic
	})

	t.Run("Get resource status", func(t *testing.T) {
		status := monitor.GetResourceStatus()

		if status["memory_limit"] == nil {
			t.Error("Expected memory limit to be set")
		}
		if status["cache_limit"] == nil {
			t.Error("Expected cache limit to be set")
		}
		if status["session_limit"] == nil {
			t.Error("Expected session limit to be set")
		}
	})

	t.Run("Get alerts", func(t *testing.T) {
		alerts := monitor.GetAlerts()

		// Should return empty slice initially
		if alerts == nil {
			t.Error("Expected alerts slice to be initialized")
		}
	})
}

func TestPerformanceMetricsCalculations(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)

	t.Run("Average calculation", func(t *testing.T) {
		// Record multiple operations with known durations
		durations := []time.Duration{
			10 * time.Millisecond,
			20 * time.Millisecond,
			30 * time.Millisecond,
		}

		for _, d := range durations {
			metrics.RecordTokenVerification(d, true)
		}

		detailed := metrics.GetDetailedTimingMetrics()
		verificationStats := detailed["verification_stats"].(map[string]interface{})

		// Average should be 20ms
		avgMs := verificationStats["average_ms"].(float64)
		if avgMs < 19 || avgMs > 21 { // Allow small variance
			t.Errorf("Expected average around 20ms, got %f", avgMs)
		}
	})

	t.Run("Min/Max calculation", func(t *testing.T) {
		logger := NewLogger("debug")
		metrics := NewPerformanceMetrics(logger) // Fresh instance

		durations := []time.Duration{
			5 * time.Millisecond,
			50 * time.Millisecond,
			25 * time.Millisecond,
		}

		for _, d := range durations {
			metrics.RecordTokenVerification(d, true)
		}

		detailed := metrics.GetDetailedTimingMetrics()
		verificationStats := detailed["verification_stats"].(map[string]interface{})

		minMs := verificationStats["min_ms"].(float64)
		maxMs := verificationStats["max_ms"].(float64)

		if minMs < 4 || minMs > 6 {
			t.Errorf("Expected min around 5ms, got %f", minMs)
		}
		if maxMs < 49 || maxMs > 51 {
			t.Errorf("Expected max around 50ms, got %f", maxMs)
		}
	})
}

func TestPerformanceMetricsReset(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)

	// Record some data
	metrics.RecordCacheHit()
	metrics.RecordTokenVerification(10*time.Millisecond, true)

	// Verify data is there
	result := metrics.GetMetrics()
	if result["cache_hits"].(int64) != 1 {
		t.Error("Expected cache hit to be recorded")
	}

	// Note: The current implementation doesn't have a reset method,
	// but we can test that metrics accumulate correctly
	metrics.RecordCacheHit()
	result = metrics.GetMetrics()
	if result["cache_hits"].(int64) != 2 {
		t.Error("Expected cache hits to accumulate")
	}
}

func TestPerformanceMetricsConcurrency(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			for j := 0; j < 100; j++ {
				metrics.RecordCacheHit()
				metrics.RecordTokenVerification(time.Millisecond, true)
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	result := metrics.GetMetrics()

	// Should have 1000 cache hits (10 goroutines * 100 operations)
	if result["cache_hits"].(int64) != 1000 {
		t.Errorf("Expected 1000 cache hits, got %v", result["cache_hits"])
	}

	// Should have 1000 token verifications
	if result["token_verifications"].(int64) != 1000 {
		t.Errorf("Expected 1000 token verifications, got %v", result["token_verifications"])
	}
}

func TestResourceMonitorLimits(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)
	monitor := NewResourceMonitor(metrics, logger)

	t.Run("Memory limit validation", func(t *testing.T) {
		// Set a reasonable memory limit
		monitor.SetMemoryLimit(50 * 1024 * 1024) // 50MB

		status := monitor.GetResourceStatus()
		if status["memory_limit"].(uint64) != 50*1024*1024 {
			t.Error("Memory limit not set correctly")
		}
	})

	t.Run("Cache limit validation", func(t *testing.T) {
		monitor.SetCacheLimit(2000)

		status := monitor.GetResourceStatus()
		if status["cache_limit"].(int) != 2000 {
			t.Error("Cache limit not set correctly")
		}
	})

	t.Run("Session limit validation", func(t *testing.T) {
		monitor.SetSessionLimit(1000)

		status := monitor.GetResourceStatus()
		if status["session_limit"].(int) != 1000 {
			t.Error("Session limit not set correctly")
		}
	})
}

func TestPerformanceMetricsEdgeCases(t *testing.T) {
	logger := NewLogger("debug")
	metrics := NewPerformanceMetrics(logger)

	t.Run("Zero duration handling", func(t *testing.T) {
		metrics.RecordTokenVerification(0, true)

		result := metrics.GetMetrics()
		if result["token_verifications"].(int64) != 1 {
			t.Error("Should record verification even with zero duration")
		}
	})

	t.Run("Very large duration handling", func(t *testing.T) {
		largeDuration := time.Hour
		metrics.RecordTokenVerification(largeDuration, true)

		detailed := metrics.GetDetailedTimingMetrics()
		verificationStats := detailed["verification_stats"].(map[string]interface{})

		// Should handle large durations without overflow
		if verificationStats["max_ms"].(float64) <= 0 {
			t.Error("Should handle large durations correctly")
		}
	})

	t.Run("Negative cache size handling", func(t *testing.T) {
		// This shouldn't happen in practice, but test robustness
		metrics.UpdateCacheSize(-1)

		result := metrics.GetMetrics()
		// Implementation should handle this gracefully
		if result["cache_size"] == nil {
			t.Error("Cache size should be present even if negative")
		}
	})
}
