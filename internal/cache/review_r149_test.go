package cache

import (
	"testing"
	"time"
)

// TestCacheClose_NilStopCleanupNoPanic guards the R149 fix in Close():
// stopCleanup is only allocated when EnableAutoCleanup && CleanupInterval > 0,
// but Close() previously closed it whenever EnableAutoCleanup was set. A
// cache built with EnableAutoCleanup=true and CleanupInterval left at its
// zero value therefore called close(nil) and panicked during shutdown.
func TestCacheClose_NilStopCleanupNoPanic(t *testing.T) {
	c := New(Config{EnableAutoCleanup: true}) // CleanupInterval defaults to 0
	if err := c.Close(); err != nil {
		t.Fatalf("Close() with CleanupInterval=0 must not panic and return nil, got: %v", err)
	}
}

// TestCacheClose_WithCleanupIntervalClosesOnce ensures the normal path
// (cleanup started) still closes cleanly exactly once.
func TestCacheClose_WithCleanupIntervalClosesOnce(t *testing.T) {
	c := New(Config{EnableAutoCleanup: true, CleanupInterval: time.Minute})
	if err := c.Close(); err != nil {
		t.Fatalf("Close() with a started cleanup goroutine must succeed, got: %v", err)
	}
	if err := c.Close(); err == nil {
		t.Fatal("second Close() must report already-closed")
	}
}
