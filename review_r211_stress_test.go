package traefikoidc

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRefreshCoordinatorStressCoordinated is a concurrency hammer on the
// refresh coordinator's dedup path: many goroutines call CoordinateRefresh
// with the SAME session+token (force collision on the sync.Map
// in-flight/session trackers and leader gates) while a concurrent
// Shutdown tears it down — the WaitGroup-balance + sync.Map race surface
// (R211). Run under -race.
func TestRefreshCoordinatorStressCoordinated(t *testing.T) {
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), GetSingletonNoOpLogger())
	defer rc.Shutdown()

	ctx := context.Background()
	var refs atomic.Int64
	refreshFunc := func() (*TokenResponse, error) {
		refs.Add(1)
		return &TokenResponse{AccessToken: "new-at", RefreshToken: "new-rt", IDToken: "id"}, nil
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_, _ = rc.CoordinateRefresh(ctx, "session-1", token, refreshFunc)
			}
		}("the-same-refresh-token")
	}
	wg.Wait()

	if got := refs.Load(); got < 1 {
		t.Fatalf("expected at least one real refresh to have run; got %d", got)
	}
	t.Logf("coordination sweep: %d real refreshes for 800 concurrent calls", refs.Load())
}
