//go:build ignore

// Command yaegicheck verifies that the traefikoidc plugin can be imported and
// instantiated by the yaegi interpreter — the same way Traefik loads a plugin.
//
// It is run by `make yaegi-validate`. Importing the plugin package forces yaegi
// to interpret every source file in the package (and its vendored
// dependencies), so any construct yaegi cannot handle (unsupported stdlib
// symbol, reflection edge case, etc.) surfaces here rather than at Traefik load
// time. CreateConfig + New additionally exercise the instantiation path
// (session manager, cookie codec, caches, key derivation) under the interpreter.
//
// Beyond the load/instantiate path, this also drives CircuitBreaker and
// RetryExecutor directly (FIX-09, FIX-14). yaegi v0.16.1 panics on
// errors.As(err, &target) whenever target's pointed-to type is itself
// interpreted ("errors: *target must be interface or implement error"), a
// case native `go test`/`go build` cannot see because there the target type
// is compiled, not interpreted. CircuitBreaker.ExecuteWithContext and
// RetryExecutor.ExecuteSingleUseWithContext both ran such a check on every
// fn() error, on the default-on token-exchange/refresh path, so this must
// run under the real interpreter to catch it.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	oidc "github.com/lukaszraczylo/traefikoidc"
	recovery "github.com/lukaszraczylo/traefikoidc/internal/recovery"
	servers "github.com/lukaszraczylo/traefikoidc/internal/testutil/servers"
)

// failingSetBackend is a minimal CacheBackend whose Set always fails with a
// plain (non-timeout) error. It guards FIX-04: UniversalCache.Set must not
// panic when isTimeoutOrDeadlineError inspects a non-timeout backend Set
// error under the yaegi interpreter.
type failingSetBackend struct{}

func (failingSetBackend) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return errors.New("x")
}
func (failingSetBackend) Get(_ context.Context, _ string) ([]byte, time.Duration, bool, error) {
	return nil, 0, false, nil
}
func (failingSetBackend) Delete(_ context.Context, _ string) (bool, error) { return false, nil }
func (failingSetBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (failingSetBackend) Clear(_ context.Context) error                    { return nil }
func (failingSetBackend) GetStats() map[string]interface{}                 { return nil }
func (failingSetBackend) Close() error                                     { return nil }
func (failingSetBackend) Ping(_ context.Context) error                     { return nil }

// checkUniversalCacheSetDoesNotPanicOnBackendError guards FIX-04: in Redis
// mode, UniversalCache.Set must degrade to the local write on any
// non-timeout backend Set error instead of panicking. errors.As against an
// anonymous interface target panics under yaegi v0.16.1, so a native `go
// test` run cannot see this; only the interpreter can.
func checkUniversalCacheSetDoesNotPanicOnBackendError() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("FAIL: UniversalCache.Set panicked on a non-timeout backend Set error:", r)
			os.Exit(1)
		}
	}()

	cache := oidc.NewUniversalCacheWithBackend(oidc.UniversalCacheConfig{
		Logger:     oidc.NewLogger("error"),
		Type:       oidc.CacheTypeToken,
		DefaultTTL: time.Minute,
	}, failingSetBackend{})
	defer cache.Close()

	if err := cache.Set("yaegi-check-key", "v", time.Minute); err != nil {
		fmt.Println("FAIL: UniversalCache.Set returned an unexpected error:", err)
		os.Exit(1)
	}
	fmt.Println("OK: UniversalCache.Set did not panic on a non-timeout backend Set error under yaegi")
}

func main() {
	cfg := oidc.CreateConfig()
	cfg.ProviderURL = "https://accounts.google.com"
	cfg.ClientID = "yaegi-check-client"
	cfg.ClientSecret = "yaegi-check-secret"
	cfg.CallbackURL = "/oauth2/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.RateLimit = 100

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h, err := oidc.New(context.Background(), next, cfg, "yaegi-check")
	if err != nil {
		fmt.Println("FAIL: New returned an error under yaegi:", err)
		os.Exit(1)
	}
	if h == nil {
		fmt.Println("FAIL: New returned a nil handler under yaegi")
		os.Exit(1)
	}
	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	fmt.Println("OK: traefikoidc imported + CreateConfig + New succeeded under yaegi")

	checkUniversalCacheSetDoesNotPanicOnBackendError()

	runCheck("fix09-plain-error", checkFix09PlainError)
	runCheck("fix09-halfopen-400-stays-halfopen", checkFix09HalfOpenTerminalStaysHalfOpen)
	runCheck("fix09-closed-400-stays-closed", checkFix09ClosedTerminalStaysClosed)
	runCheck("fix09-429-reopens", checkFix09RateLimitReopens)
	runCheck("fix14-httperror-once", checkFix14HTTPErrorNeverRetried)
	runCheck("fix14-real-dial-retried", checkFix14RealDialRetried)

	// NEW-01: errors.As(err, &target) panics under yaegi v0.16.1 whenever
	// target's pointed-to type is interpreted (*HTTPError, *OIDCError are
	// both declared in this plugin / internal/recovery, so always are),
	// regardless of err's own concrete type. These checks drive every
	// reachable errors.As-replacement site directly under the interpreter.
	runCheck("new01-retryexecutor-500-retried", checkNew01RetryExecutorHTTPError500Retried)
	runCheck("new01-retryexecutor-400-not-retried", checkNew01RetryExecutorHTTPError400NotRetried)
	runCheck("new01-retryexecutor-plain-error-no-panic", checkNew01RetryExecutorPlainErrorNoPanic)
	runCheck("new01-internal-recovery-httperror-classification", checkNew01InternalRecoveryHTTPErrorClassification)
	runCheck("new01-internal-recovery-oidcerror-classification", checkNew01InternalRecoveryOIDCErrorClassification)
	runCheck("new01-introspection-bearer-4xx-no-panic", checkNew01IntrospectionBearer4xxNoPanic)
	runCheck("new01-introspection-bearer-5xx-no-panic", checkNew01IntrospectionBearer5xxNoPanic)

	fmt.Println("OK: all yaegi regression checks passed")
}

// runCheck runs one named regression check and exits the process on
// failure, matching this command's existing OK/FAIL reporting style. detail
// is appended to the PASS line verbatim (e.g. " calls=3"), or empty.
func runCheck(name string, fn func() (string, error)) {
	detail, err := fn()
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("PASS %s%s\n", name, detail)
}

// circuitStateName renders a CircuitBreakerState for FAIL messages.
func circuitStateName(s oidc.CircuitBreakerState) string {
	switch s {
	case oidc.CircuitBreakerClosed:
		return "closed"
	case oidc.CircuitBreakerOpen:
		return "open"
	case oidc.CircuitBreakerHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// checkFix09PlainError drives CircuitBreaker.ExecuteWithContext with a
// plain (non-HTTPError) error, the call shape that panicked first under the
// pre-fix isTerminalClientError: errors.As against an interpreted *HTTPError
// target panics under yaegi regardless of the error's own concrete type,
// because the check runs on every fn() error.
func checkFix09PlainError() (string, error) {
	cb := oidc.NewCircuitBreaker(oidc.CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      50 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, oidc.NewLogger("error"))

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("boom")
	})
	if err == nil {
		return "", fmt.Errorf("expected the plain error to be returned")
	}
	if cb.GetState() != oidc.CircuitBreakerOpen {
		return "", fmt.Errorf("expected a plain error to trip the breaker open, got %s", circuitStateName(cb.GetState()))
	}
	return "", nil
}

// newHalfOpenBreaker builds a breaker, trips it with one real (non client)
// failure, and waits past Timeout so the next ExecuteWithContext call
// performs the Open -> HalfOpen probe transition itself.
func newHalfOpenBreaker() *oidc.CircuitBreaker {
	cb := oidc.NewCircuitBreaker(oidc.CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      100 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, oidc.NewLogger("error"))

	_ = cb.ExecuteWithContext(context.Background(), func() error {
		return &oidc.HTTPError{StatusCode: 500, Message: "downstream unavailable"}
	})
	time.Sleep(150 * time.Millisecond)
	return cb
}

// checkFix09HalfOpenTerminalStaysHalfOpen pins FIX-09: a terminal client 4xx
// (e.g. invalid_grant) must not reopen a half-open circuit.
func checkFix09HalfOpenTerminalStaysHalfOpen() (string, error) {
	cb := newHalfOpenBreaker()

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &oidc.HTTPError{StatusCode: 400, Message: "invalid_grant"}
	})
	if err == nil {
		return "", fmt.Errorf("expected the probe's own error to be returned")
	}
	if cb.GetState() != oidc.CircuitBreakerHalfOpen {
		return "", fmt.Errorf("a terminal client 4xx must not reopen a half-open circuit, got %s", circuitStateName(cb.GetState()))
	}
	return "", nil
}

// checkFix09ClosedTerminalStaysClosed pins that the same exemption applies
// in the Closed state: a terminal client 4xx must not trip the breaker.
func checkFix09ClosedTerminalStaysClosed() (string, error) {
	cb := oidc.NewCircuitBreaker(oidc.CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      50 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, oidc.NewLogger("error"))

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &oidc.HTTPError{StatusCode: 400, Message: "invalid_grant"}
	})
	if err == nil {
		return "", fmt.Errorf("expected the probe's own error to be returned")
	}
	if cb.GetState() != oidc.CircuitBreakerClosed {
		return "", fmt.Errorf("a terminal client 4xx must not trip a closed circuit, got %s", circuitStateName(cb.GetState()))
	}
	return "", nil
}

// checkFix09RateLimitReopens guards against over-broadening FIX-09: a 429
// (the service itself signaling overload) must still reopen a half-open
// circuit.
func checkFix09RateLimitReopens() (string, error) {
	cb := newHalfOpenBreaker()

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &oidc.HTTPError{StatusCode: 429, Message: "rate limited"}
	})
	if err == nil {
		return "", fmt.Errorf("expected the probe's own error to be returned")
	}
	if cb.GetState() != oidc.CircuitBreakerOpen {
		return "", fmt.Errorf("a 429 must still reopen a half-open circuit, got %s", circuitStateName(cb.GetState()))
	}
	return "", nil
}

// checkFix14HTTPErrorNeverRetried pins FIX-14: a *HTTPError proves a
// response was received, so ExecuteSingleUseWithContext must never retry
// it even when its Message (up to 10 KiB of a real IdP response body, see
// helpers.go) happens to contain a singleUseRetryableErrors fragment such
// as "connection refused".
func checkFix14HTTPErrorNeverRetried() (string, error) {
	re := oidc.NewRetryExecutor(oidc.RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      1 * time.Millisecond,
		BackoffFactor: 1,
	}, oidc.NewLogger("error"))

	calls := 0
	err := re.ExecuteSingleUseWithContext(context.Background(), func() error {
		calls++
		return &oidc.HTTPError{
			StatusCode: 500,
			Message:    "token endpoint returned status 500: {\"error\":\"server_error\",\"detail\":\"upstream: connection refused\"}",
		}
	})
	if err == nil {
		return "", fmt.Errorf("expected the HTTPError to be returned")
	}
	if calls != 1 {
		return "", fmt.Errorf("fn called %d times, want 1", calls)
	}
	return fmt.Sprintf(" calls=%d", calls), nil
}

// checkFix14RealDialRetried guards against over-broadening FIX-14: a real
// client.Do dial failure (net/http wraps it as *net.OpError, reached via
// errors.As unwrapping any %w chain) proves the request never reached the
// server and must still be retried.
func checkFix14RealDialRetried() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("setup: %w", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	re := oidc.NewRetryExecutor(oidc.RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      1 * time.Millisecond,
		BackoffFactor: 1,
	}, oidc.NewLogger("error"))

	client := &http.Client{Timeout: 3 * time.Second}
	calls := 0
	execErr := re.ExecuteSingleUseWithContext(context.Background(), func() error {
		calls++
		resp, derr := client.Get("http://" + addr + "/")
		if derr != nil {
			return fmt.Errorf("token endpoint request failed: %w", derr)
		}
		resp.Body.Close()
		return nil
	})
	if execErr == nil {
		return "", fmt.Errorf("expected the dial failure to be returned after exhausting retries")
	}
	if calls != 3 {
		return "", fmt.Errorf("fn called %d times, want 3", calls)
	}
	return fmt.Sprintf(" calls=%d", calls), nil
}

// checkNew01RetryExecutorHTTPError500Retried pins NEW-01: RetryExecutor's
// isRetryableError classifies an *HTTPError via asHTTPError, a plain type
// assertion plus an errors.Unwrap walk, NOT errors.As -- errors.As(err,
// &target) panics under yaegi v0.16.1 whenever target's pointed-to type is
// interpreted, and *HTTPError is declared in this plugin so it always is,
// regardless of err's own concrete type (error_recovery.go, isRetryableError
// ~line 764/821). A 500 is a transient server error and must be retried to
// MaxAttempts.
func checkNew01RetryExecutorHTTPError500Retried() (string, error) {
	re := oidc.NewRetryExecutor(oidc.RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      1 * time.Millisecond,
		BackoffFactor: 1,
	}, oidc.NewLogger("error"))

	calls := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		calls++
		return &oidc.HTTPError{StatusCode: 500, Message: "downstream unavailable"}
	})
	if err == nil {
		return "", fmt.Errorf("expected the HTTPError to be returned after exhausting retries")
	}
	if calls != 3 {
		return "", fmt.Errorf("fn called %d times, want 3 (a 500 must be retried)", calls)
	}
	return fmt.Sprintf(" calls=%d", calls), nil
}

// checkNew01RetryExecutorHTTPError400NotRetried is checkNew01RetryExecutorHTTPError500Retried's
// counterpart: a terminal 4xx (other than 429) must NOT be retried.
func checkNew01RetryExecutorHTTPError400NotRetried() (string, error) {
	re := oidc.NewRetryExecutor(oidc.RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      1 * time.Millisecond,
		BackoffFactor: 1,
	}, oidc.NewLogger("error"))

	calls := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		calls++
		return &oidc.HTTPError{StatusCode: 400, Message: "invalid_grant"}
	})
	if err == nil {
		return "", fmt.Errorf("expected the HTTPError to be returned")
	}
	if calls != 1 {
		return "", fmt.Errorf("fn called %d times, want 1 (a terminal 400 must not be retried)", calls)
	}
	return fmt.Sprintf(" calls=%d", calls), nil
}

// checkNew01RetryExecutorPlainErrorNoPanic pins that a plain (non-HTTPError)
// error reaching isRetryableError's asHTTPError check never panics under
// yaegi -- the exact call shape that panicked pre-fix regardless of err's
// own concrete type (see asHTTPError's doc comment, error_recovery.go).
func checkNew01RetryExecutorPlainErrorNoPanic() (string, error) {
	re := oidc.NewRetryExecutor(oidc.RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      1 * time.Millisecond,
		BackoffFactor: 1,
	}, oidc.NewLogger("error"))

	calls := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		calls++
		return errors.New("boom")
	})
	if err == nil {
		return "", fmt.Errorf("expected the plain error to be returned")
	}
	if calls != 1 {
		return "", fmt.Errorf("fn called %d times, want 1 (an unrecognized plain error must not be retried)", calls)
	}
	return fmt.Sprintf(" calls=%d", calls), nil
}

// checkNew01InternalRecoveryHTTPErrorClassification covers
// internal/recovery/metrics.go's RetryExecutor.isRetryableError, which has
// its OWN *HTTPError type (interpreted, same yaegi hazard as the top-level
// package's) and is reachable under yaegi because the traefikoidc plugin
// imports internal/recovery transitively (internal/utils/logger_wrapper.go),
// forcing yaegi to interpret it when the plugin loads.
func checkNew01InternalRecoveryHTTPErrorClassification() (string, error) {
	retryCfg := recovery.RetryConfig{
		MaxAttempts:          3,
		InitialDelay:         1 * time.Millisecond,
		MaxDelay:             1 * time.Millisecond,
		Multiplier:           1,
		RetryableStatusCodes: []int{500, 503},
	}

	calls500 := 0
	err := recovery.NewRetryExecutor(retryCfg, nil).ExecuteWithContext(context.Background(), func() error {
		calls500++
		return &recovery.HTTPError{StatusCode: 500, Message: "downstream unavailable"}
	})
	if err == nil {
		return "", fmt.Errorf("500: expected the HTTPError to be returned after exhausting retries")
	}
	if calls500 != 3 {
		return "", fmt.Errorf("500: fn called %d times, want 3", calls500)
	}

	calls400 := 0
	err = recovery.NewRetryExecutor(retryCfg, nil).ExecuteWithContext(context.Background(), func() error {
		calls400++
		return &recovery.HTTPError{StatusCode: 400, Message: "bad request"}
	})
	if err == nil {
		return "", fmt.Errorf("400: expected the HTTPError to be returned")
	}
	if calls400 != 1 {
		return "", fmt.Errorf("400: fn called %d times, want 1", calls400)
	}

	return fmt.Sprintf(" calls500=%d calls400=%d", calls500, calls400), nil
}

// checkNew01InternalRecoveryOIDCErrorClassification is
// checkNew01InternalRecoveryHTTPErrorClassification's counterpart for
// internal/recovery's *OIDCError (also interpreted, also reached via
// errors.As pre-fix).
func checkNew01InternalRecoveryOIDCErrorClassification() (string, error) {
	retryCfg := recovery.RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     1 * time.Millisecond,
		Multiplier:   1,
	}

	callsRetryable := 0
	err := recovery.NewRetryExecutor(retryCfg, nil).ExecuteWithContext(context.Background(), func() error {
		callsRetryable++
		return &recovery.OIDCError{Code: "temporarily_unavailable", Description: "busy"}
	})
	if err == nil {
		return "", fmt.Errorf("retryable: expected the OIDCError to be returned after exhausting retries")
	}
	if callsRetryable != 3 {
		return "", fmt.Errorf("retryable: fn called %d times, want 3", callsRetryable)
	}

	callsTerminal := 0
	err = recovery.NewRetryExecutor(retryCfg, nil).ExecuteWithContext(context.Background(), func() error {
		callsTerminal++
		return &recovery.OIDCError{Code: "invalid_grant", Description: "nope"}
	})
	if err == nil {
		return "", fmt.Errorf("terminal: expected the OIDCError to be returned")
	}
	if callsTerminal != 1 {
		return "", fmt.Errorf("terminal: fn called %d times, want 1", callsTerminal)
	}

	return fmt.Sprintf(" callsRetryable=%d callsTerminal=%d", callsRetryable, callsTerminal), nil
}

// checkNew01IntrospectionBearerStatus builds a full plugin instance with
// bearer auth + mandatory introspection enabled, points IntrospectionURL at
// a controllable server returning wantStatus, and drives one bearer request
// carrying an opaque (non-JWT) token through introspectToken end-to-end
// under yaegi. introspectToken is the shared producer for BOTH the bearer
// path (bearer_auth.go) and the session path (token_validation_rs.go, the
// NEW-01 fix site); this proves the round trip -- discovery, introspection
// POST, error classification, response write -- never panics under the real
// interpreter for a 4xx or a 5xx introspection response.
func checkNew01IntrospectionBearerStatus(wantStatus int) (string, error) {
	discovery := servers.NewOIDCServer(nil)
	defer discovery.Close()

	introspect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
	}))
	defer introspect.Close()

	cfg := oidc.CreateConfig()
	cfg.ProviderURL = discovery.URL
	cfg.ClientID = "yaegi-check-bearer-client"
	cfg.ClientSecret = "yaegi-check-bearer-secret"
	cfg.CallbackURL = "/oauth2/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.RateLimit = 100
	cfg.EnableBearerAuth = true
	cfg.Audience = cfg.ClientID
	cfg.RequireTokenIntrospection = true
	cfg.AllowOpaqueTokens = true
	cfg.IntrospectionURL = introspect.URL

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h, err := oidc.New(context.Background(), next, cfg, fmt.Sprintf("yaegi-check-bearer-%d", wantStatus))
	if err != nil {
		return "", fmt.Errorf("New: %w", err)
	}
	if closer, ok := h.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer opaque-test-token-without-dots")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code == 0 {
		return "", fmt.Errorf("ServeHTTP did not write a response")
	}
	return fmt.Sprintf(" introspection_status=%d response_status=%d", wantStatus, rw.Code), nil
}

func checkNew01IntrospectionBearer4xxNoPanic() (string, error) {
	return checkNew01IntrospectionBearerStatus(http.StatusTooManyRequests)
}

func checkNew01IntrospectionBearer5xxNoPanic() (string, error) {
	return checkNew01IntrospectionBearerStatus(http.StatusInternalServerError)
}
