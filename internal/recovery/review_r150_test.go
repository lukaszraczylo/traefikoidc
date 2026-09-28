package recovery

import (
	"testing"
	"time"
)

// TestRetryExecutor_HighRandomizationNoNegativeDelay guards the R150 fix in
// RetryExecutor.calculateDelay: with RandomizationFactor > 1 the raw
// minDelay = delay*(1-RF) is negative, letting time.After(negative)
// fire immediately and defeating backoff. Delays must be clamped to
// >= 0.
func TestRetryExecutor_HighRandomizationNoNegativeDelay(t *testing.T) {
	exec := NewRetryExecutor(RetryConfig{
		InitialDelay:        100 * time.Millisecond,
		MaxDelay:            2 * time.Second,
		Multiplier:          2.0,
		RandomizationFactor: 2.5, // > 1: un-fixed code yields negative delays
	}, &mockLogger{})
	for attempt := 1; attempt <= 2000; attempt++ {
		if d := exec.calculateDelay(attempt); d < 0 {
			t.Fatalf("attempt %d produced negative delay %v", attempt, d)
		}
	}
}
