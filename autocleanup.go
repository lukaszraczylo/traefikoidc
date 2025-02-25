package traefikoidc

import "time"

// autoCleanupRoutine runs a ticker that calls the provided cleanup function at the specified interval.
// It stops when a value is received on the stop channel.
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
