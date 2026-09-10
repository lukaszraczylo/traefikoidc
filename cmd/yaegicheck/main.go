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
	"sync"
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
	runCheck("new01-opaque-session-introspection-classification", checkNew01OpaqueSessionIntrospectionClassification)

	runCheck("fix06-sse-flush-reaches-next", checkSSEFlushReachesNext)
	runCheck("fix17-setifabsent-claims-once", checkSetIfAbsentUnderYaegi)
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

	// Every introspectToken error on the bearer path -- 4xx or 5xx alike --
	// maps to bearerErrIntrospectionUnavailable, a 503 (bearer_auth.go). A
	// recovered errors.As panic answers a DIFFERENT status: ServeHTTP's own
	// deferred recover turns any panic into 500 (middleware.go), and
	// httptest.NewRecorder starts at Code 200, so neither of those values
	// can be mistaken for the real 503. rw.Code == 0 (the previous check
	// here) can never happen -- the Recorder never leaves that zero value --
	// so it accepted a recovered panic silently. Require the exact expected
	// value instead.
	if rw.Code != http.StatusServiceUnavailable {
		return "", fmt.Errorf("expected response_status=%d (bearerErrIntrospectionUnavailable) for introspection_status=%d, got %d", http.StatusServiceUnavailable, wantStatus, rw.Code)
	}
	return fmt.Sprintf(" introspection_status=%d response_status=%d", wantStatus, rw.Code), nil
}

func checkNew01IntrospectionBearer4xxNoPanic() (string, error) {
	return checkNew01IntrospectionBearerStatus(http.StatusTooManyRequests)
}

func checkNew01IntrospectionBearer5xxNoPanic() (string, error) {
	return checkNew01IntrospectionBearerStatus(http.StatusInternalServerError)
}

// checkNew01OpaqueSessionIntrospectionClassification drives the SESSION
// path fixed by commit d7686c3, which checkNew01IntrospectionBearerStatus
// above does not reach: an authenticated cookie session holding an opaque
// access token, validated via isUserAuthenticatedRS ->
// validateStandardTokensRS -> validateOpaqueToken, when introspection
// answers a 5xx. Before d7686c3, validateStandardTokensRS classified
// validateOpaqueToken's error with errors.As(err, &httpErr) against
// *HTTPError -- interpreted under yaegi v0.16.1, so this panicked on every
// opaque-token session-path classification regardless of introspection
// status. The bearer path shares introspectToken but never reaches this
// call site, so a yaegicheck suite that only drove the bearer path could
// not have caught this.
//
// A cookie session is built directly (New's session manager is an
// unexported field, unreachable from this package) with a second
// SessionManager sharing the exact cfg fields oidc.New passes into its own
// NewSessionManager call (SessionEncryptionKey, ForceHTTPS, CookieDomain,
// CookiePrefix, SessionMaxAge). The cookie codec key is a deterministic
// function of those inputs alone (deriveCookieKeys, no per-instance
// randomness), so a cookie minted here decodes identically in the plugin's
// own session manager.
func checkNew01OpaqueSessionIntrospectionClassification() (string, error) {
	discovery := servers.NewOIDCServer(nil)
	defer discovery.Close()

	introspect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer introspect.Close()

	cfg := oidc.CreateConfig()
	cfg.ProviderURL = discovery.URL
	cfg.ClientID = "yaegi-check-session-client"
	cfg.ClientSecret = "yaegi-check-session-secret"
	cfg.CallbackURL = "/oauth2/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.RateLimit = 100
	cfg.AllowOpaqueTokens = true
	cfg.RequireTokenIntrospection = true
	cfg.IntrospectionURL = introspect.URL

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h, err := oidc.New(context.Background(), next, cfg, "yaegi-check-session")
	if err != nil {
		return "", fmt.Errorf("New: %w", err)
	}
	if closer, ok := h.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	sm, err := oidc.NewSessionManager(cfg.SessionEncryptionKey, cfg.ForceHTTPS, cfg.CookieDomain, cfg.CookiePrefix, time.Duration(cfg.SessionMaxAge)*time.Second, oidc.NewLogger("error"))
	if err != nil {
		return "", fmt.Errorf("NewSessionManager: %w", err)
	}
	defer sm.Shutdown()

	setupReq := httptest.NewRequest("GET", "/protected", nil)
	session, err := sm.GetSession(setupReq)
	if err != nil {
		return "", fmt.Errorf("GetSession: %w", err)
	}
	if err := session.SetAuthenticated(true); err != nil {
		return "", fmt.Errorf("SetAuthenticated: %w", err)
	}
	// No dots: isOpaqueToken (validateStandardTokensRS) reads it as opaque,
	// routing it into validateOpaqueToken/introspectToken instead of JWT
	// parsing. No refresh token is set, so a classification of "not
	// verifiable, requireTokenIntrospection fails closed" resolves
	// deterministically to expired (not needsRefresh) below.
	session.SetAccessToken("opaque-session-token-without-dots")
	rec := httptest.NewRecorder()
	if err := session.Save(setupReq, rec); err != nil {
		return "", fmt.Errorf("session.Save: %w", err)
	}
	session.ReturnToPool()

	req := httptest.NewRequest("GET", "/protected", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	// requireTokenIntrospection=true with no refresh token classifies a
	// 5xx-introspection opaque access token as expired (not "token
	// invalid", which is reserved for a definitive active=false/expired/
	// revoked introspection body -- RFC 7662 s2.2/s2.3): ServeHTTP responds
	// with handleExpiredToken -> defaultInitiateAuthentication, a 302 to
	// the provider. A reintroduced errors.As panic is instead recovered by
	// ServeHTTP's own deferred recover as a 500, before t.next is ever
	// reached -- a status this check must reject just as firmly as the 200
	// (rw.Code's unwritten zero value can never appear here either) a
	// silently-swallowed panic could otherwise produce.
	if rw.Code != http.StatusFound {
		return "", fmt.Errorf("expected response_status=%d (re-authentication redirect) for a 5xx introspection response on the session path, got %d", http.StatusFound, rw.Code)
	}
	return fmt.Sprintf(" response_status=%d", rw.Code), nil
}

// checkSSEFlushReachesNext pins FIX-06: the writer ServeHTTP hands to next
// must support http.NewResponseController(w).Flush() under yaegi. Before
// the fix, next received the interpreted *trackingWriter, which exposes no
// Flusher across the interpreter boundary, so SSE responses were buffered
// in Traefik. The excluded-URL bypass reaches next without a session.
func checkSSEFlushReachesNext() (string, error) {
	cfg := oidc.CreateConfig()
	cfg.ProviderURL = "https://accounts.google.com"
	cfg.ClientID = "yaegi-check-client"
	cfg.ClientSecret = "yaegi-check-secret"
	cfg.CallbackURL = "/oauth2/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.ExcludedURLs = []string{"/public"}

	var flushErr error
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: 1\n\n"))
		flushErr = http.NewResponseController(w).Flush()
	})
	h, err := oidc.New(context.Background(), next, cfg, "yaegi-sse")
	if err != nil {
		return "", fmt.Errorf("New: %v", err)
	}
	if closer, ok := h.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/public/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	h.ServeHTTP(rec, req)
	if !reached {
		return "", fmt.Errorf("next was not reached (status %d)", rec.Code)
	}
	if flushErr != nil {
		return "", fmt.Errorf("Flush on the writer handed to next failed: %v", flushErr)
	}
	if !rec.Flushed {
		return "", fmt.Errorf("the underlying writer was not flushed")
	}
	return "", nil
}

// memNXBackend is a minimal in-process CacheBackend that also implements
// SetNX, standing in for a Redis backend. It guards FIX-17: the
// optional-interface assertion in UniversalCache.SetIfAbsent must work
// under yaegi, and a second claim of the same key must lose.
type memNXBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (b *memNXBackend) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[k] = v
	return nil
}

func (b *memNXBackend) Get(_ context.Context, k string) ([]byte, time.Duration, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.data[k]
	return v, 0, ok, nil
}

func (b *memNXBackend) Delete(_ context.Context, k string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[k]
	delete(b.data, k)
	return ok, nil
}

func (b *memNXBackend) Exists(_ context.Context, k string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[k]
	return ok, nil
}

func (b *memNXBackend) Clear(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = map[string][]byte{}
	return nil
}

func (b *memNXBackend) GetStats() map[string]interface{} { return nil }
func (b *memNXBackend) Close() error                     { return nil }
func (b *memNXBackend) Ping(_ context.Context) error     { return nil }

func (b *memNXBackend) SetNX(_ context.Context, k string, v []byte, _ time.Duration) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.data[k]; ok {
		return false, nil
	}
	b.data[k] = v
	return true, nil
}

// claimTwice calls SetIfAbsent twice on the same key and returns both
// results. The first call must claim the key and the second must lose.
func claimTwice(c *oidc.UniversalCache) (bool, bool, error) {
	first, err := c.SetIfAbsent("yaegi-jti", true, time.Minute)
	if err != nil {
		return false, false, err
	}
	second, err := c.SetIfAbsent("yaegi-jti", true, time.Minute)
	return first, second, err
}

// checkSetIfAbsentUnderYaegi pins FIX-17: UniversalCache.SetIfAbsent must
// claim a key exactly once in local-only mode and through a backend that
// implements SetNX, and must refuse a backend without SetNX instead of
// claiming locally.
func checkSetIfAbsentUnderYaegi() (string, error) {
	cfg := oidc.UniversalCacheConfig{
		Logger:          oidc.NewLogger("error"),
		Type:            oidc.CacheTypeToken,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}

	local := oidc.NewUniversalCache(cfg)
	defer local.Close()
	if first, second, err := claimTwice(local); err != nil || !first || second {
		return "", fmt.Errorf("local-only: first=%v second=%v err=%v, want true false nil", first, second, err)
	}

	nx := oidc.NewUniversalCacheWithBackend(cfg, &memNXBackend{data: map[string][]byte{}})
	defer nx.Close()
	if first, second, err := claimTwice(nx); err != nil || !first || second {
		return "", fmt.Errorf("SetNX backend: first=%v second=%v err=%v, want true false nil", first, second, err)
	}

	noNX := oidc.NewUniversalCacheWithBackend(cfg, failingSetBackend{})
	defer noNX.Close()
	claimed, err := noNX.SetIfAbsent("yaegi-jti", true, time.Minute)
	if err == nil || claimed {
		return "", fmt.Errorf("backend without SetNX: claimed=%v err=%v, want false and an error", claimed, err)
	}
	return "", nil
}
