package traefikoidc

import (
	"testing"
	"time"
)

// TestRefreshCoordinatorShutdownIdempotent guards against a panic when the
// coordinator is shut down more than once. Close() on the same
// Authenticator can be reached via both the plugin-context cancellation hook
// (main.go) and the resource-manager teardown path, so RefreshCoordinator
// Shutdown must tolerate repeated calls — the previous close(rc.stopChan)
// panicked with 'close of closed channel' on the second call.
func TestRefreshCoordinatorShutdownIdempotent(t *testing.T) {
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), NewLogger(DefaultLogLevel))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Shutdown panicked: %v", r)
		}
	}()
	rc.Shutdown()
	rc.Shutdown()
}

// Ensure cleanup goroutine is running before shutdown completes so the
// shutdown path is actually exercised (stopChan close) and wg drained.
func TestRefreshCoordinatorShutdownStopsCleanup(t *testing.T) {
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), NewLogger(DefaultLogLevel))
	time.Sleep(50 * time.Millisecond)
	rc.Shutdown()
}
