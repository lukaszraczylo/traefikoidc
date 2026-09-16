package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// --- R117 fix #4: allowOpaqueTokens without a client secret must be rejected ---

// buildValidSecretlessPrivateKeyJWTConfig returns a config that, absent the
// opaque-token gate, would validate: private_key_jwt carries its own key so a
// missing client secret is otherwise permitted.
func buildValidPrivateKeyJWTConfig() *Config {
	return &Config{
		ProviderURL:      "https://provider.example.com",
		CallbackURL:      "/callback",
		ClientID:         "client-1",
		ClientAuthMethod: "private_key_jwt",
		ClientAssertionPrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwduphekeyz
-----END PRIVATE KEY-----`,
		ClientAssertionKeyID: "kid-1",
		SessionEncryptionKey: "01234567890123456789012345678901",
		RateLimit:            MinRateLimit,
		LogLevel:             "error",
	}
}

// TestConfig_AllowOpaqueTokensRequiresSecret regresses R117: opaque tokens are
// introspected via client_secret_basic (token_introspection.go SetBasicAuth),
// so a config that enables allowOpaqueTokens without a client secret would
// send empty Basic credentials and reject every opaque token. Previously the
// gate covered only requireTokenIntrospection; allowOpaqueTokens alone was
// accepted and silently broken.
func TestConfig_AllowOpaqueTokensRequiresSecret(t *testing.T) {
	cfg := buildValidPrivateKeyJWTConfig()
	cfg.AllowOpaqueTokens = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected allowOpaqueTokens without clientSecret to fail validation")
	}
}

func TestConfig_AllowOpaqueTokensWithSecret_Valid(t *testing.T) {
	cfg := buildValidPrivateKeyJWTConfig()
	cfg.AllowOpaqueTokens = true
	cfg.ClientSecret = "a-secret"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("allowOpaqueTokens with a client secret should validate, got %v", err)
	}
}

// --- R117 fix #3: bearer auth-rejection responses must not be cached ---

func TestWriteBearerError_CacheControlNoStore(t *testing.T) {
	oidc := &TraefikOidc{logger: NewLogger("error")}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()

	oidc.writeBearerError(rw, req, newBearerError(bearerErrThrottled, "rate limited"))

	if got := rw.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control: no-store on bearer error, got %q", got)
	}
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rw.Code)
	}
}

// --- R117 fix #2: bearerFailureTracker must bound its per-IP map ---

func TestBearerFailureTracker_PruneStaleEntries(t *testing.T) {
	tr := newBearerFailureTracker(20, 60*time.Second, 60*time.Second)

	// Seed more than the sweep threshold, all stale (penalty anyway expired
	// well before window+penalty).
	for i := 0; i < defaultBearerEntrySweepThreshold+100; i++ {
		tr.entries[ipKey(i)] = &bearerFailureEntry{
			firstFailureAt: time.Now().Add(-10 * time.Minute),
			penaltyUntil:   time.Now().Add(-5 * time.Minute),
			count:          1,
		}
	}

	// A new failure on a fresh IP should trigger the sweep and drop the
	// stale entries.
	tr.recordFailure("fresh-ip")

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if n := len(tr.entries); n > defaultBearerEntrySweepThreshold {
		t.Fatalf("expected map to be pruned below sweep threshold, got %d entries", n)
	}
	if _, ok := tr.entries["stale-1"]; ok {
		t.Fatal("expected stale entry to be pruned")
	}
}

func ipKey(i int) string {
	return "10.0." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)
}

// --- R117 fix #5: BackgroundTask.Stop must not hang on a blocked task ---

func TestBackgroundTask_StopReturnsForBlockedTask(t *testing.T) {
	block := make(chan struct{})
	defer close(block) // release the in-flight goroutine after the assertion
	entered := make(chan struct{})
	bt := NewBackgroundTask("blocked-task", time.Hour, func() {
		close(entered) // signal that taskFunc is now executing (can't observe stopChan)
		<-block
	}, NewLogger("error"))

	bt.Start()

	// Wait until taskFunc is genuinely in flight before stopping, so stopChan
	// has no immediate effect (the task is mid-execution and can't see it).
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("task never started in flight (circuit breaker denied start?)")
	}

	stopped := make(chan struct{})
	go func() {
		bt.Stop()
		close(stopped)
	}()

	// Stop must return (after its bounded 5s timeout) rather than hanging
	// on internalWG.Wait() while the task is blocked.
	select {
	case <-stopped:
		// OK: Stop returned despite the still-running task.
	case <-time.After(9 * time.Second):
		t.Fatal("BackgroundTask.Stop hung on a blocked task (old behavior waited on internalWG forever)")
	}
}
