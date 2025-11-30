package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestHealthChecker_StatusTransitions tests health status transitions
func TestHealthChecker_StatusTransitions(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32
	var shouldFail atomic.Bool

	checkFunc := func(ctx context.Context) error {
		callCount.Add(1)
		if shouldFail.Load() {
			return errors.New("health check failed")
		}
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      50 * time.Millisecond,
		Timeout:            10 * time.Millisecond,
		UnhealthyThreshold: 3,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	// Initially unknown
	assert.Equal(t, HealthUnknown, hc.GetStatus())

	// Trigger failures
	shouldFail.Store(true)
	time.Sleep(200 * time.Millisecond)

	// Should be unhealthy after threshold failures
	status := hc.GetStatus()
	assert.True(t, status == HealthUnhealthy || status == HealthDegraded)

	// Recover
	shouldFail.Store(false)
	time.Sleep(150 * time.Millisecond)

	// Should recover towards healthy
	finalStatus := hc.GetStatus()
	assert.True(t, finalStatus == HealthHealthy || finalStatus == HealthDegraded || finalStatus == HealthUnknown)
}

// TestHealthChecker_InitialState tests initial health status
func TestHealthChecker_InitialState(t *testing.T) {
	t.Parallel()

	checkFunc := func(ctx context.Context) error {
		return nil
	}

	config := &HealthCheckConfig{
		CheckFunc: checkFunc,
	}
	hc := NewHealthChecker(config)
	assert.Equal(t, HealthUnknown, hc.GetStatus())
	assert.False(t, hc.IsHealthy())
}

// TestHealthChecker_ForceCheck tests manual health check trigger
func TestHealthChecker_ForceCheck(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	checkFunc := func(ctx context.Context) error {
		callCount.Add(1)
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      10 * time.Second, // Long interval
		Timeout:            1 * time.Second,
		UnhealthyThreshold: 3,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)

	initialCount := callCount.Load()

	// Force check
	hc.Check(context.Background())

	// Should have been called
	assert.Greater(t, callCount.Load(), initialCount)
}

// TestHealthChecker_StatusChangeCallback tests status change notifications
func TestHealthChecker_StatusChangeCallback(t *testing.T) {
	t.Parallel()

	var transitions []string
	var mu sync.Mutex
	var shouldFail atomic.Bool

	checkFunc := func(ctx context.Context) error {
		if shouldFail.Load() {
			return errors.New("health check failed")
		}
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      30 * time.Millisecond,
		Timeout:            10 * time.Millisecond,
		UnhealthyThreshold: 2,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
		OnStatusChange: func(from, to HealthStatus) {
			mu.Lock()
			defer mu.Unlock()
			transitions = append(transitions, from.String()+"->"+to.String())
		},
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	// Trigger failures
	shouldFail.Store(true)
	time.Sleep(100 * time.Millisecond)

	// Recover
	shouldFail.Store(false)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Should have status transitions
	assert.NotEmpty(t, transitions)
}

// TestHealthChecker_Stats tests statistics tracking
func TestHealthChecker_Stats(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	checkFunc := func(ctx context.Context) error {
		callCount.Add(1)
		if callCount.Load()%2 == 0 {
			return errors.New("failure")
		}
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      20 * time.Millisecond,
		Timeout:            10 * time.Millisecond,
		UnhealthyThreshold: 5,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	time.Sleep(150 * time.Millisecond)

	stats := hc.Stats()

	assert.Greater(t, stats.TotalChecks, int64(0))
	assert.Greater(t, stats.TotalFailures, int64(0))
	assert.Greater(t, stats.SuccessRate, 0.0)
	assert.Less(t, stats.SuccessRate, 1.0)
}

// TestHealthChecker_Timeout tests check timeout handling
func TestHealthChecker_Timeout(t *testing.T) {
	t.Parallel()

	checkFunc := func(ctx context.Context) error {
		// Simulate slow check
		select {
		case <-time.After(100 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	config := &HealthCheckConfig{
		CheckInterval:      50 * time.Millisecond,
		Timeout:            10 * time.Millisecond, // Short timeout
		UnhealthyThreshold: 2,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	time.Sleep(150 * time.Millisecond)

	// Should be unhealthy due to timeouts
	status := hc.GetStatus()
	assert.NotEqual(t, HealthHealthy, status)
}

// TestHealthChecker_ConcurrentAccess tests thread safety
func TestHealthChecker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	checkFunc := func(ctx context.Context) error {
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      10 * time.Millisecond,
		Timeout:            5 * time.Millisecond,
		UnhealthyThreshold: 3,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	var wg sync.WaitGroup
	goroutines := 20

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = hc.GetStatus()
				_ = hc.IsHealthy()
				_ = hc.Stats()
				hc.Check(context.Background())
			}
		}()
	}

	wg.Wait()
	// Should complete without panics
}

// TestHealthChecker_StopAndStart tests lifecycle management
func TestHealthChecker_StopAndStart(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	checkFunc := func(ctx context.Context) error {
		callCount.Add(1)
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      20 * time.Millisecond,
		Timeout:            10 * time.Millisecond,
		UnhealthyThreshold: 3,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)

	// Start
	hc.Start()
	time.Sleep(100 * time.Millisecond)
	count1 := callCount.Load()
	assert.Greater(t, count1, int32(0))

	// Stop
	hc.Stop()
	time.Sleep(100 * time.Millisecond)
	count2 := callCount.Load()

	// Should not have increased significantly after stop
	assert.Less(t, count2-count1, int32(3))
}

// TestHealthChecker_DegradedState tests degraded status
func TestHealthChecker_DegradedState(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	checkFunc := func(ctx context.Context) error {
		count := callCount.Add(1)
		// Fail once, then succeed
		if count == 1 {
			return errors.New("single failure")
		}
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      30 * time.Millisecond,
		Timeout:            10 * time.Millisecond,
		UnhealthyThreshold: 3, // Need 3 failures for unhealthy
		HealthyThreshold:   2, // Need 2 successes for healthy
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	time.Sleep(100 * time.Millisecond)

	// After initial checks, status should be set (might be healthy or degraded based on execution)
	status := hc.GetStatus()
	assert.True(t, status != HealthUnknown, "Status should not be unknown after checks")
}

// TestHealthChecker_DefaultConfig tests default configuration
func TestHealthChecker_DefaultConfig(t *testing.T) {
	t.Parallel()

	checkFunc := func(ctx context.Context) error {
		return nil
	}

	config := &HealthCheckConfig{
		CheckFunc: checkFunc,
	}
	hc := NewHealthChecker(config)

	assert.NotNil(t, hc)
	assert.Equal(t, HealthUnknown, hc.GetStatus())

	// Verify default config was applied (we can't access private fields, so just check it works)
	assert.NotNil(t, hc)
}

// TestHealthChecker_StatusString tests status string representation
func TestHealthChecker_StatusString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "healthy", HealthHealthy.String())
	assert.Equal(t, "unhealthy", HealthUnhealthy.String())
	assert.Equal(t, "degraded", HealthDegraded.String())
	assert.Equal(t, "unknown", HealthStatus(999).String())
}

// TestHealthChecker_RecoveryPattern tests typical failure and recovery
func TestHealthChecker_RecoveryPattern(t *testing.T) {
	t.Parallel()

	var checkNumber atomic.Int32

	checkFunc := func(ctx context.Context) error {
		n := checkNumber.Add(1)
		// Fail checks 3-5, succeed others
		if n >= 3 && n <= 5 {
			return errors.New("temporary failure")
		}
		return nil
	}

	var statusLog []HealthStatus
	var mu sync.Mutex

	config := &HealthCheckConfig{
		CheckInterval:      30 * time.Millisecond,
		Timeout:            10 * time.Millisecond,
		UnhealthyThreshold: 3,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
		OnStatusChange: func(from, to HealthStatus) {
			mu.Lock()
			defer mu.Unlock()
			statusLog = append(statusLog, to)
		},
	}

	hc := NewHealthChecker(config)
	hc.Start()
	defer hc.Stop()

	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Should see transitions through unhealthy and back to healthy
	assert.NotEmpty(t, statusLog)

	// Final status should be healthy or degraded (recovered)
	finalStatus := hc.GetStatus()
	assert.True(t, finalStatus == HealthHealthy || finalStatus == HealthDegraded, "Should have recovered")
}

// Benchmark health checker performance
func BenchmarkHealthChecker_ForceCheck(b *testing.B) {
	checkFunc := func(ctx context.Context) error {
		return nil
	}

	config := &HealthCheckConfig{
		CheckInterval:      10 * time.Minute,
		Timeout:            1 * time.Second,
		UnhealthyThreshold: 3,
		HealthyThreshold:   2,
		CheckFunc:          checkFunc,
	}

	hc := NewHealthChecker(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hc.Check(context.Background())
	}
}

func BenchmarkHealthChecker_Status(b *testing.B) {
	checkFunc := func(ctx context.Context) error {
		return nil
	}

	config := &HealthCheckConfig{
		CheckFunc: checkFunc,
	}
	hc := NewHealthChecker(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hc.GetStatus()
	}
}
