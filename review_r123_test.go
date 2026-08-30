package traefikoidc

import (
	"net/http/httptest"
	"testing"
)

// TestRetryExecutor_Terminal4xxNotRetriedByMessage guards the R123 fix to
// error_recovery.go isRetryableError: the configured message-substring scan
// ran BEFORE the HTTP status check, so a terminal 4xx whose provider body
// merely contained a retryable-looking word (e.g. a 400 whose message
// includes "timeout") was reclassified retryable and retried to MaxAttempts
// on a permanent error. A real (non-0) status that is neither 5xx nor 429
// must win over message text.
func TestRetryExecutor_Terminal4xxNotRetriedByMessage(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{RetryableErrors: []string{"timeout"}}, GetSingletonNoOpLogger())

	if re.isRetryableError(&HTTPError{StatusCode: 400, Message: "invalid grant: token timeout"}) {
		t.Fatal("terminal 400 with a retryable-looking body must NOT be classified retryable")
	}
	if !re.isRetryableError(&HTTPError{StatusCode: 503, Message: "timeout"}) {
		t.Fatal("503 must remain retryable")
	}
	// Status-0 message carrier: the substring scan must still apply so a
	// message-loaded (no real HTTP status) error with a retryable word
	// keeps its historical retryable behavior.
	if !re.isRetryableError(&HTTPError{StatusCode: 0, Message: "request timeout"}) {
		t.Fatal("status-0 message carrier with a retryable word must remain retryable")
	}
}

// TestConfigValidate_RejectsNonPositiveHSTSMaxAge guards the R123 fix to
// settings.go Config.Validate: an enabled HSTS with a non-positive
// StrictTransportSecurityMaxAge emitted "Strict-Transport-Security:
// max-age=0" (or negative) verbatim, which per RFC 6797 s.6.1 tells the
// UA to REMOVE the HSTS policy — the operator's protection silently
// disabled with no error. It must be rejected at validation.
func validTestConfig() *Config {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://auth.example.com"
	cfg.CallbackURL = "/callback"
	cfg.ClientID = "test-client"
	cfg.ClientSecret = "test-client-secret"
	cfg.SessionEncryptionKey = "test-encryption-key-32-bytes-long!!"
	return cfg
}

func TestConfigValidate_RejectsNonPositiveHSTSMaxAge(t *testing.T) {
	cfg := validTestConfig()
	cfg.SecurityHeaders.StrictTransportSecurity = true
	cfg.SecurityHeaders.StrictTransportSecurityMaxAge = 3
	if err := cfg.Validate(); err != nil {
		t.Fatalf("positive max-age must validate: %v", err)
	}

	for _, bad := range []int{0, -1} {
		cfg := validTestConfig()
		cfg.SecurityHeaders.StrictTransportSecurity = true
		cfg.SecurityHeaders.StrictTransportSecurityMaxAge = bad
		if err := cfg.Validate(); err == nil {
			t.Fatalf("max-age=%d with HSTS enabled must fail validation", bad)
		}
	}
}

// TestConfigValidate_RedisEnvAppliedBeforeValidate guards the R123 fix to
// settings.go Config.Validate: an operator enabling Redis via REDIS_ENABLED
// (documented) had c.Redis.Enabled==false at config load, so the Redis
// validation guards (address required) were skipped and the backend was
// built with an empty address, silently falling back to memory-only at
// runtime. Validate must apply env fallbacks before gating on Enabled.
func TestConfigValidate_RedisEnvAppliedBeforeValidate(t *testing.T) {
	t.Setenv("REDIS_ENABLED", "true")
	t.Setenv("REDIS_ADDRESS", "")

	cfg := validTestConfig()
	cfg.Redis = &RedisConfig{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("env-enabled Redis with an empty address must fail validation")
	}

	// With an address the same env config must pass.
	t.Setenv("REDIS_ADDRESS", "redis://127.0.0.1:6379")
	cfg = validTestConfig()
	cfg.Redis = &RedisConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("env-enabled Redis with an address must validate: %v", err)
	}
}

// TestValidateRedirectCount_PersistsReset guards the R123 fix to
// auth_flow.go validateRedirectCount: on exceeding the redirect limit the
// counter was ResetRedirectCount() but never Saved, so the cookie kept the
// old count and every subsequent request re-observed the limit, hard-
// locking the user on 508 for the whole session with no recovery. The
// reset must be persisted so the next request starts fresh.
func TestValidateRedirectCount_PersistsReset(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		NewLogger("error"),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	tOidc := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		sessionManager: sessionManager,
	}

	req := httptest.NewRequest("GET", "/", nil)
	rw := httptest.NewRecorder()
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	defer session.returnToPoolSafely()

	// Set the counter at/over the limit.
	session.mainSession.Values["redirect_count"] = 5

	// Trigger the limit path; it must persist the reset via Save.
	if err := tOidc.validateRedirectCount(session, rw, req); err == nil {
		t.Fatal("validateRedirectCount must return an error when the limit is reached")
	}

	// The reset must have been flushed to a session cookie on this response.
	cookies := rw.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("validateRedirectCount must emit a session cookie carrying the reset")
	}

	// A subsequent request carrying that cookie must see the counter reset.
	afterReq := httptest.NewRequest("GET", "/", nil)
	afterReq.Header.Set("Cookie", cookies[0].String())
	afterSess, err := sessionManager.GetSession(afterReq)
	if err != nil {
		t.Fatalf("get after session: %v", err)
	}
	defer afterSess.returnToPoolSafely()

	if c := afterSess.GetRedirectCount(); c != 0 {
		t.Fatalf("reset must be persisted (next request starts at 0), got %d", c)
	}
}
