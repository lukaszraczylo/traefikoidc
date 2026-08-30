package traefikoidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestExecuteWithRecovery_RetryCountsOnce guards the R144 fix in
// error_recovery.go ExecuteWithRecovery: the circuit breaker was nested
// INSIDE the retry loop, so each retry attempt recorded a separate
// failure — a single flaky-but-retryable call with two attempts opened
// the circuit (2 failures) in one logical operation. The correct
// compositing (matching TokenResilienceManager's R106 rule) is retry
// inner, circuit outer: one logical call must count as ONE circuit
// failure regardless of internal retries.
func TestExecuteWithRecovery_RetryCountsOnce(t *testing.T) {
	logger := newNoOpLogger()
	mgr := &ErrorRecoveryManager{
		circuitBreakers: map[string]*CircuitBreaker{
			"svc": NewCircuitBreaker(CircuitBreakerConfig{
				MaxFailures:  2,
				Timeout:      time.Second,
				ResetTimeout: time.Second,
			}, logger),
		},
		retryExecutor: NewRetryExecutor(RetryConfig{
			MaxAttempts:     2,
			InitialDelay:    time.Millisecond,
			MaxDelay:        time.Millisecond,
			BackoffFactor:   1,
			EnableJitter:    false,
			RetryableErrors: []string{"boom"},
		}, logger),
		gracefulDegradation: NewGracefulDegradation(DefaultGracefulDegradationConfig(), logger),
		logger:              logger,
	}

	_ = mgr.ExecuteWithRecovery(context.Background(), "svc", func() error {
		return errors.New("boom")
	})

	cb := mgr.circuitBreakers["svc"]
	if got := cb.failures; got != 1 {
		t.Fatalf("one logical call with an internal retry must record exactly one circuit failure, got %d (circuit opened prematurely per retry attempt)", got)
	}
}

// TestCookiePath_StripsInboundAuthorization guards the R144 fix in
// middleware.go forwardAuthorized: the raw inbound Authorization header
// was only stripped on the bearer path, while the cookie/session path
// forwarded a client-supplied Authorization verbatim. A session user
// could therefore present an arbitrary — possibly more privileged —
// bearer that a downstream verifier might trust over X-Forwarded-User,
// or leak a raw token into downstream logs. The header must be stripped
// for the session path too when stripAuthorizationHeader is set.
func TestCookiePath_StripsInboundAuthorization(t *testing.T) {
	var captured http.Header
	oidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}),
		logger:                   newNoOpLogger(),
		minimalHeaders:           true,
		stripAuthorizationHeader: true,
	}

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Authorization", "Bearer unrelated-downstream-token")
	rw := httptest.NewRecorder()

	p := &principal{
		Source:     sourceSession,
		Identifier: "user@example.com",
	}

	oidc.forwardAuthorized(rw, req, p)

	if v := captured.Get("Authorization"); v != "" {
		t.Fatalf("cookie/session path must strip the inbound Authorization header, but downstream received %q", v)
	}
}
