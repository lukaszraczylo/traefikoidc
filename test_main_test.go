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
