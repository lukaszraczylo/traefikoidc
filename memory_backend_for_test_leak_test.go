package traefikoidc

import (
	"net"
	"testing"
	"time"
)

// TestNewMemoryBackendForTest_ClosesMiniredisOnCleanup is a regression test
// for the finding that NewMemoryBackendForTest started a miniredis server
// and never closed it: callers only deferred backend.Close(), which closes
// the RedisBackend connection pool, not the underlying miniredis listener
// and its goroutines. Each call leaked a listener for the rest of the test
// binary.
//
// NewMemoryBackendForTest must register the miniredis server against the
// given *testing.T's Cleanup, so the server (and its listener goroutine) is
// closed when the owning test ends, not left running indefinitely.
func TestNewMemoryBackendForTest_ClosesMiniredisOnCleanup(t *testing.T) {
	var addr string

	t.Run("inner", func(st *testing.T) {
		backend, err := NewMemoryBackendForTest(st)
		if err != nil {
			st.Fatalf("NewMemoryBackendForTest: %v", err)
		}
		st.Cleanup(func() { _ = backend.Close() })

		a, ok := backend.GetStats()["address"].(string)
		if !ok || a == "" {
			st.Fatalf("backend.GetStats()[\"address\"] not a non-empty string: %v", backend.GetStats()["address"])
		}
		addr = a
	})

	// The "inner" subtest has returned, so its t.Cleanup callbacks (in LIFO
	// order: our backend.Close(), then whatever NewMemoryBackendForTest
	// registered) have already run. If NewMemoryBackendForTest closed the
	// miniredis server as part of that cleanup, nothing should be
	// listening on addr anymore.
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("miniredis at %s is still accepting connections after the owning subtest's cleanup ran; NewMemoryBackendForTest leaked the miniredis listener", addr)
	}
}
