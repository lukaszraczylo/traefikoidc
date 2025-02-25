package traefikoidc

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestAutoCleanupRoutine(t *testing.T) {
	var counter int32
	cleanupFunc := func() {
		atomic.AddInt32(&counter, 1)
	}
	stop := make(chan struct{})
	go autoCleanupRoutine(50*time.Millisecond, stop, cleanupFunc)
	time.Sleep(250 * time.Millisecond)
	close(stop)

	if atomic.LoadInt32(&counter) < 3 {
		t.Errorf("Expected cleanup to be called at least 3 times, got %d", counter)
	}
}
