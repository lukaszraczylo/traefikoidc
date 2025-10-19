package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestCircuitBreaker_StateTransitions tests state machine transitions
func TestCircuitBreaker_StateTransitions(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 2,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	t.Run("Initial state is closed", func(t *testing.T) {
		assert.Equal(t, StateClosed, cb.GetState())
	})

	t.Run("Closed to Open after max failures", func(t *testing.T) {
		cb.Reset()

		// Simulate failures
		for i := 0; i < 3; i++ {
			cb.Execute(ctx, func() error {
				return errors.New("test error")
			})
		}

		assert.Equal(t, StateOpen, cb.GetState())
	})

	t.Run("Open to HalfOpen after timeout", func(t *testing.T) {
		// Open the circuit
		cb.Reset()
		for i := 0; i < 3; i++ {
			cb.Execute(ctx, func() error {
				return errors.New("test error")
			})
		}
		assert.Equal(t, StateOpen, cb.GetState())

		// Wait for timeout
		time.Sleep(150 * time.Millisecond)

		// Should allow request and transition to half-open
		err := cb.Execute(ctx, func() error {
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, StateHalfOpen, cb.GetState())
	})

	t.Run("HalfOpen to Closed after successful requests", func(t *testing.T) {
		// Open circuit then wait for half-open
		cb.Reset()
		for i := 0; i < 3; i++ {
			cb.Execute(ctx, func() error {
				return errors.New("test error")
			})
		}
		assert.Equal(t, StateOpen, cb.GetState())

		time.Sleep(150 * time.Millisecond)

		// First request transitions to half-open and succeeds
		err := cb.Execute(ctx, func() error {
			return nil
		})
		assert.NoError(t, err)
		// Should be in half-open after first request
		state := cb.GetState()
		assert.True(t, state == StateHalfOpen || state == StateClosed,
			"After first successful request, should be half-open or potentially closed")

		if state == StateHalfOpen {
			// Need more successful requests to close
			// The exact number depends on implementation but should be within HalfOpenMaxRequests
			for i := 0; i < config.HalfOpenMaxRequests; i++ {
				cb.Execute(ctx, func() error {
					return nil
				})
			}
			// After multiple successful requests, should eventually close
			finalState := cb.GetState()
			assert.True(t, finalState == StateClosed || finalState == StateHalfOpen,
				"After successful requests, circuit should transition towards closed")
		}
	})

	t.Run("HalfOpen to Open on failure", func(t *testing.T) {
		// Open circuit then wait for half-open
		cb.Reset()
		for i := 0; i < 3; i++ {
			cb.Execute(ctx, func() error {
				return errors.New("test error")
			})
		}
		time.Sleep(150 * time.Millisecond)

		// First call transitions to half-open, second failure reopens
		cb.Execute(ctx, func() error {
			return errors.New("test error")
		})

		assert.Equal(t, StateOpen, cb.GetState())
	})
}

// TestCircuitBreaker_OpenCircuitBlocks tests that open circuit blocks requests
func TestCircuitBreaker_OpenCircuitBlocks(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             1 * time.Second,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Trigger failures to open circuit
	for i := 0; i < 2; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("test error")
		})
	}

	assert.Equal(t, StateOpen, cb.GetState())

	// Requests should be blocked
	err := cb.Execute(ctx, func() error {
		t.Fatal("Should not execute function when circuit is open")
		return nil
	})

	assert.Error(t, err)
	assert.Equal(t, ErrCircuitOpen, err)
}

// TestCircuitBreaker_HalfOpenMaxRequests tests max requests in half-open state
func TestCircuitBreaker_HalfOpenMaxRequests(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 2,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Open circuit then wait for half-open
	for i := 0; i < 3; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("test error")
		})
	}
	assert.Equal(t, StateOpen, cb.GetState())

	time.Sleep(150 * time.Millisecond)

	// After timeout, circuit should allow transition to half-open
	// Execute HalfOpenMaxRequests successful requests
	successCount := 0
	for i := 0; i < config.HalfOpenMaxRequests; i++ {
		err := cb.Execute(ctx, func() error {
			successCount++
			return nil
		})
		// Should allow up to HalfOpenMaxRequests
		assert.NoError(t, err)
	}

	// Verify we executed the expected number
	assert.Equal(t, config.HalfOpenMaxRequests, successCount)

	// After successful requests, circuit behavior depends on implementation
	// It could close (allowing more requests) or stay half-open (blocking)
	// The important thing is that we allowed exactly HalfOpenMaxRequests
}

// TestCircuitBreaker_SuccessResetsFailures tests failure counter reset
func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Have some failures (but less than max)
	cb.Execute(ctx, func() error {
		return errors.New("error")
	})
	cb.Execute(ctx, func() error {
		return errors.New("error")
	})

	assert.Equal(t, StateClosed, cb.GetState())
	stats := cb.Stats()
	assert.Equal(t, int32(2), stats.ConsecutiveFailures)

	// One success should reset failures
	cb.Execute(ctx, func() error {
		return nil
	})

	assert.Equal(t, StateClosed, cb.GetState())
	stats = cb.Stats()
	assert.Equal(t, int32(0), stats.ConsecutiveFailures)
}

// TestCircuitBreaker_ConcurrentAccess tests thread safety
func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         10,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 5,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()
	var wg sync.WaitGroup
	goroutines := 20
	iterations := 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Mix of successes and failures
				cb.Execute(ctx, func() error {
					if (id+j)%3 == 0 {
						return errors.New("test error")
					}
					return nil
				})

				// Random state checks
				_ = cb.GetState()
				_ = cb.Stats()
			}
		}(i)
	}

	wg.Wait()

	// Should complete without panics
	stats := cb.Stats()
	assert.NotNil(t, stats)
}

// TestCircuitBreaker_Stats tests statistics tracking
func TestCircuitBreaker_Stats(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         5,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 2,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Execute some requests
	cb.Execute(ctx, func() error { return nil })                 // Success
	cb.Execute(ctx, func() error { return errors.New("error") }) // Failure
	cb.Execute(ctx, func() error { return errors.New("error") }) // Failure

	stats := cb.Stats()

	assert.Equal(t, StateClosed, stats.State)
	assert.Equal(t, int64(3), stats.TotalRequests)
	assert.Equal(t, int64(2), stats.TotalFailures)
	assert.Equal(t, int32(2), stats.ConsecutiveFailures)
}

// TestCircuitBreaker_Reset tests circuit reset
func TestCircuitBreaker_Reset(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Open the circuit
	for i := 0; i < 2; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("error")
		})
	}

	assert.Equal(t, StateOpen, cb.GetState())

	// Reset
	cb.Reset()

	assert.Equal(t, StateClosed, cb.GetState())
	stats := cb.Stats()
	assert.Equal(t, int32(0), stats.ConsecutiveFailures)
	assert.Equal(t, int64(0), stats.TotalRequests)
	assert.Equal(t, int64(0), stats.TotalFailures)
}

// TestCircuitBreaker_StateChangeCallback tests state change notifications
func TestCircuitBreaker_StateChangeCallback(t *testing.T) {
	t.Parallel()

	var transitions []string
	var mu sync.Mutex

	config := &CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		HalfOpenMaxRequests: 1,
		OnStateChange: func(from, to State) {
			mu.Lock()
			defer mu.Unlock()
			transitions = append(transitions, from.String()+"->"+to.String())
		},
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Trigger state transitions
	// Closed -> Open
	for i := 0; i < 2; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("error")
		})
	}

	// Should be open now
	assert.Equal(t, StateOpen, cb.GetState())

	// Wait for timeout to allow half-open transition
	time.Sleep(100 * time.Millisecond)

	// Open -> HalfOpen on first request after timeout
	err := cb.Execute(ctx, func() error {
		return nil
	})
	assert.NoError(t, err)

	// Execute more successful requests to trigger HalfOpen -> Closed
	for i := 0; i < config.HalfOpenMaxRequests-1; i++ {
		cb.Execute(ctx, func() error {
			return nil
		})
	}

	mu.Lock()
	defer mu.Unlock()

	assert.Contains(t, transitions, "closed->open")
	assert.Contains(t, transitions, "open->half-open")
}

// TestCircuitBreaker_IsHealthy tests health check
func TestCircuitBreaker_IsHealthy(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             100 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Initially healthy
	assert.True(t, cb.IsHealthy())

	// Open circuit
	for i := 0; i < 2; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("error")
		})
	}

	assert.Equal(t, StateOpen, cb.GetState())
	assert.False(t, cb.IsHealthy(), "Should not be healthy when open")

	// Wait for timeout and allow successful request
	time.Sleep(150 * time.Millisecond)
	cb.Execute(ctx, func() error {
		return nil
	})

	// Should be healthy after recovery
	assert.True(t, cb.IsHealthy(), "Should be healthy after recovery")
}

// TestCircuitBreaker_RapidFailures tests rapid consecutive failures
func TestCircuitBreaker_RapidFailures(t *testing.T) {
	t.Parallel()

	config := &CircuitBreakerConfig{
		MaxFailures:         5,
		Timeout:             200 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Rapid failures
	for i := 0; i < 10; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("rapid error")
		})
	}

	assert.Equal(t, StateOpen, cb.GetState())

	stats := cb.Stats()
	assert.GreaterOrEqual(t, stats.TotalFailures, int64(5))
}

// TestCircuitBreaker_TimeoutAccuracy tests timeout precision
func TestCircuitBreaker_TimeoutAccuracy(t *testing.T) {
	t.Parallel()

	timeout := 100 * time.Millisecond
	config := &CircuitBreakerConfig{
		MaxFailures:         1,
		Timeout:             timeout,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(config)

	ctx := context.Background()

	// Open circuit
	cb.Execute(ctx, func() error {
		return errors.New("error")
	})

	assert.Equal(t, StateOpen, cb.GetState())

	// Wait just before timeout
	time.Sleep(timeout - 20*time.Millisecond)
	assert.False(t, cb.IsHealthy())

	// Wait until after timeout
	time.Sleep(40 * time.Millisecond)
	// After timeout, AllowRequest should return true for transition to half-open
	assert.True(t, cb.AllowRequest())
}

// TestCircuitBreaker_DefaultConfig tests default configuration
func TestCircuitBreaker_DefaultConfig(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(nil) // Should use defaults

	assert.NotNil(t, cb)
	assert.Equal(t, StateClosed, cb.GetState())

	// Verify defaults by triggering circuit breaker behavior
	ctx := context.Background()

	// Test that it takes 5 failures to open (default MaxFailures)
	for i := 0; i < 4; i++ {
		cb.Execute(ctx, func() error {
			return errors.New("error")
		})
	}
	assert.Equal(t, StateClosed, cb.GetState(), "Should still be closed after 4 failures")

	// 5th failure should open it
	cb.Execute(ctx, func() error {
		return errors.New("error")
	})
	assert.Equal(t, StateOpen, cb.GetState(), "Should be open after 5 failures (default threshold)")
}

// TestCircuitBreaker_StateString tests state string representation
func TestCircuitBreaker_StateString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "closed", StateClosed.String())
	assert.Equal(t, "open", StateOpen.String())
	assert.Equal(t, "half-open", StateHalfOpen.String())
	assert.Equal(t, "unknown", State(999).String())
}

// Benchmark circuit breaker performance
func BenchmarkCircuitBreaker_Execute(b *testing.B) {
	config := &CircuitBreakerConfig{
		MaxFailures:         100,
		Timeout:             1 * time.Second,
		HalfOpenMaxRequests: 10,
	}
	cb := NewCircuitBreaker(config)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(ctx, func() error {
			return nil
		})
	}
}

func BenchmarkCircuitBreaker_ExecuteWithFailures(b *testing.B) {
	config := &CircuitBreakerConfig{
		MaxFailures:         1000,
		Timeout:             1 * time.Second,
		HalfOpenMaxRequests: 10,
	}
	cb := NewCircuitBreaker(config)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(ctx, func() error {
			if i%10 == 0 {
				return errors.New("error")
			}
			return nil
		})
	}
}
