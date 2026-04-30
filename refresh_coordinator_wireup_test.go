package traefikoidc

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubTokenExchanger lets us count how many upstream refresh-token grants
// happen for a given refresh_token across concurrent middleware-level calls.
type stubTokenExchanger struct {
	calls int32
	delay time.Duration
	resp  *TokenResponse
}

func (s *stubTokenExchanger) ExchangeCodeForToken(_ context.Context, _, _, _, _ string) (*TokenResponse, error) {
	return nil, nil
}

func (s *stubTokenExchanger) GetNewTokenWithRefreshToken(_ string) (*TokenResponse, error) {
	atomic.AddInt32(&s.calls, 1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.resp, nil
}

func (s *stubTokenExchanger) RevokeTokenWithProvider(_, _ string) error {
	return nil
}

// TestCoordinatedTokenRefresh_SingleUpstreamCall verifies the wireup: many
// concurrent calls to coordinatedTokenRefresh with the same refresh token
// must collapse to a single tokenExchanger.GetNewTokenWithRefreshToken call.
//
// Without the wireup this assertion fails (one upstream call per goroutine).
func TestCoordinatedTokenRefresh_SingleUpstreamCall(t *testing.T) {
	stub := &stubTokenExchanger{
		delay: 100 * time.Millisecond,
		resp: &TokenResponse{
			AccessToken:  "new_access",
			RefreshToken: "new_refresh",
			IDToken:      "new_id",
			ExpiresIn:    3600,
		},
	}

	logger := NewLogger("error")
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.MaxRefreshAttempts = 10000
	cfg.MaxConcurrentRefreshes = 32

	oidc := &TraefikOidc{
		logger:             logger,
		tokenExchanger:     stub,
		refreshCoordinator: NewRefreshCoordinator(cfg, logger),
	}
	defer oidc.refreshCoordinator.Shutdown()

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	req := httptest.NewRequest("GET", "/", nil)
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-start
			resp, err := oidc.coordinatedTokenRefresh(req, "shared_refresh_token")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if resp == nil || resp.AccessToken != "new_access" {
				t.Errorf("unexpected response: %+v", resp)
			}
		}()
	}

	close(start)
	wg.Wait()

	got := atomic.LoadInt32(&stub.calls)
	// Up to 2 is acceptable to absorb the documented timing slack in the
	// existing coordinator tests (e.g. operation just cleaned up before a
	// late goroutine reads the in-flight map). Anything beyond that means
	// coalescing is broken.
	if got > 2 {
		t.Fatalf("expected <=2 upstream refresh calls, got %d", got)
	}
}

// TestCoordinatedTokenRefresh_FallsBackWithoutCoordinator verifies the nil
// coordinator path so existing tests that build TraefikOidc literals stay
// green.
func TestCoordinatedTokenRefresh_FallsBackWithoutCoordinator(t *testing.T) {
	stub := &stubTokenExchanger{
		resp: &TokenResponse{AccessToken: "ok"},
	}

	oidc := &TraefikOidc{
		logger:         NewLogger("error"),
		tokenExchanger: stub,
		// refreshCoordinator deliberately nil
	}

	resp, err := oidc.coordinatedTokenRefresh(nil, "rt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "ok" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", got)
	}
}

// TestCoordinatedTokenRefresh_DistinctTokensRunInParallel verifies that
// distinct refresh tokens are not falsely coalesced.
func TestCoordinatedTokenRefresh_DistinctTokensRunInParallel(t *testing.T) {
	stub := &stubTokenExchanger{
		delay: 20 * time.Millisecond,
		resp:  &TokenResponse{AccessToken: "ok"},
	}

	logger := NewLogger("error")
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.MaxRefreshAttempts = 10000
	cfg.MaxConcurrentRefreshes = 32
	cfg.DeduplicationCleanupDelay = 0

	oidc := &TraefikOidc{
		logger:             logger,
		tokenExchanger:     stub,
		refreshCoordinator: NewRefreshCoordinator(cfg, logger),
	}
	defer oidc.refreshCoordinator.Shutdown()

	const distinct = 8
	var wg sync.WaitGroup
	wg.Add(distinct)
	for i := 0; i < distinct; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, err := oidc.coordinatedTokenRefresh(nil, refreshCoordinatorSessionID(string(rune('a'+i))))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&stub.calls); int(got) != distinct {
		t.Fatalf("expected %d distinct upstream calls, got %d", distinct, got)
	}
}
