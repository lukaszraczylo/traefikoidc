package traefikoidc

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Fail the package when a test leaves a GracefulDegradation (from
	// NewGracefulDegradation, NewErrorRecoveryManager or
	// NewTokenResilienceManager) unclosed, or leaves the shared health-check
	// task running. A leaked instance keeps the process-global task alive
	// and makes lifecycle tests that assume a clean start flaky. Close what
	// you create with t.Cleanup. Plugin instances close asynchronously when
	// their context is canceled, so allow a short settle window.
	if code == 0 {
		if leak := waitForNoGracefulDegradationLeak(2 * time.Second); leak != "" {
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", leak)
			code = 1
		}
	}

	// Global cleanup after all tests with timeout
	done := make(chan struct{})
	go func() {
		globalCleanup.CleanupAll()
		close(done)
	}()

	select {
	case <-done:
		// Cleanup completed
	case <-time.After(10 * time.Second):
		// Cleanup timed out
		fmt.Fprintf(os.Stderr, "WARNING: Global cleanup timed out after 10 seconds\n")
	}

	os.Exit(code)
}

// waitForNoGracefulDegradationLeak waits up to timeout for every
// GracefulDegradation to be closed and the shared health-check task to stop.
// It returns an empty string when that happens, or a description of the leak.
func waitForNoGracefulDegradationLeak(timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		live := gdInstancesLen()
		running := GetResourceManager().IsTaskRunning(gdHealthTaskName)
		if live == 0 && !running {
			return ""
		}
		if time.Now().After(deadline) {
			return fmt.Sprintf("tests leaked %d unclosed GracefulDegradation instance(s); shared health-check task running=%v", live, running)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
