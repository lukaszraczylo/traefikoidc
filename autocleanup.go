package traefikoidc

import "time"

// autoCleanupRoutine periodically calls the provided cleanup function.
// It starts a ticker with the given interval and executes the cleanup function
// on each tick. The routine stops gracefully when a signal is received on the
// stop channel. This is typically used for background cleanup tasks like
// expiring cache entries.
//
// Parameters:
//   - interval: The time duration between cleanup calls.
//   - stop: A channel used to signal the routine to stop. Receiving any value will terminate the loop.
//   - cleanup: The function to call periodically for cleanup tasks.
func autoCleanupRoutine(interval time.Duration, stop <-chan struct{}, cleanup func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanup()
		case <-stop:
			return
		}
	}
}
