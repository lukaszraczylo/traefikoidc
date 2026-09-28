package traefikoidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- R118 fix A: token-endpoint 5xx must be retryable -----------------

// TestExchangeTokens_ReturnsHTTPErrorOn5xx regresses the dead retry branch:
// exchangeTokens returned a plain fmt.Errorf for non-200, so the retry
// executor's *HTTPError 5xx/429 classification (errors.As) never matched in
// production and transient IdP 5xx on refresh was never retried.
func TestExchangeTokens_ReturnsHTTPErrorOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer srv.Close()

	oidc := &TraefikOidc{
		tokenURL:        srv.URL,
		tokenHTTPClient: srv.Client(),
	}

	_, err := oidc.exchangeTokens(context.Background(), "refresh_token", "rt", "", "")
	if err == nil {
		t.Fatal("expected error from 503 token endpoint")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError so 5xx can be retried, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("HTTPError StatusCode = %d, want 503", httpErr.StatusCode)
	}
}

func TestIsRetryableError_HTTPErrorStatus(t *testing.T) {
	re := &RetryExecutor{}
	cases := []struct {
		status int
		want   bool
	}{
		{500, true},
		{503, true},
		{429, true},
		{400, false},
		{0, false}, // unset status = message carrier only, not retryable
	}
	for _, c := range cases {
		err := &HTTPError{StatusCode: c.status, Message: "m"}
		if got := re.isRetryableError(err); got != c.want {
			t.Fatalf("isRetryableError(%d) = %v, want %v", c.status, got, c.want)
		}
	}
}

// --- R118 fix C: bypass role gate must fall back to access-token claims ---

// tokenWithGroups builds a JWT whose signature segment is long enough to pass
// the session chunk manager's format validation (>=10 chars) so the access
// token round-trips through Set/GetAccessToken.
func tokenWithGroups(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	// Varied (non-repeating) signature bytes so the session chunk manager's
	// repeated-character heuristic does not reject it.
	sigBytes := make([]byte, 32)
	for i := range sigBytes {
		sigBytes[i] = byte(i + 1)
	}
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)
	return base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(pl) + "." + sig
}

// TestApplyBypassUserHeaders_AccessTokenGroupFallback regresses R118: the
// SSE/WebSocket bypass role gate read only the session's ID token, while the
// main authorization path falls back to access-token claims when no ID token
// is present. For opaque-ID-token providers (groups only in the access
// token) a legitimate user was granted on normal requests but 403'd on
// streaming, fail-closed but wrong.
func TestApplyBypassUserHeaders_AccessTokenGroupFallback(t *testing.T) {
	sm := createTestSessionManager(t)

	base := httptest.NewRequest(http.MethodGet, "/stream", nil)
	baseRec := httptest.NewRecorder()
	session, err := sm.GetSession(base)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if err := session.SetAuthenticated(true); err != nil {
		t.Fatalf("SetAuthenticated: %v", err)
	}
	session.SetUserIdentifier("user@company.com")
	// Groups live in the ACCESS token; no ID token is set.
	session.SetAccessToken(tokenWithGroups(t, map[string]interface{}{"groups": []string{"team-a"}}))
	if err := session.Save(base, baseRec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	for _, c := range baseRec.Result().Cookies() {
		req.AddCookie(c)
	}

	oidc := &TraefikOidc{
		sessionManager:        sm,
		logger:                NewLogger("debug"),
		extractClaimsFunc:     extractClaims,
		groupClaimName:        "groups", // default; set explicitly for direct construction
		allowedRolesAndGroups: map[string]struct{}{"team-a": {}},
	}

	ok, status := oidc.applyBypassUserHeaders(req, "test")
	if !ok {
		t.Fatalf("bypass role gate denied access-token group; got status %d, want granted", status)
	}
}

// --- R118 fix D: Start/StopProfiling must not self-deadlock ------------

func TestProfilingStartStop_NoSelfDeadlock(t *testing.T) {
	pm := NewProfilingManager(NewLogger("error"))

	started := make(chan error, 1)
	go func() {
		started <- pm.StartProfiling(ProfilingConfig{})
	}()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("StartProfiling error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartProfiling deadlocked (held write lock then re-acquired read lock)")
	}

	stopped := make(chan struct{})
	go func() {
		_, _ = pm.StopProfiling()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("StopProfiling deadlocked")
	}
}

// --- R118 fix E: AnalyzeLeaks must diff against baseline ---------------

func TestAnalyzeLeaks_GoroutineBaselineDiff(t *testing.T) {
	pm := NewProfilingManager(NewLogger("error"))

	// Inflate the live goroutine count deterministically so the diff is
	// meaningful regardless of ambient (possibly very low) test count.
	release := make(chan struct{})
	defer close(release)
	for i := 0; i < 30; i++ {
		go func() {
			<-release
		}()
	}

	// Baseline captured much earlier (count 0) vs a later snapshot taken
	// while 30+ goroutines are alive -> a positive, meaningful increase.
	baseline := &MemorySnapshot{Goroutines: 0}
	current := &MemorySnapshot{}

	analysis := pm.AnalyzeLeaks(baseline, current)
	if analysis.GoroutineIncrease <= 10 {
		t.Fatalf("expected goroutine increase from baseline diff, got %d", analysis.GoroutineIncrease)
	}
	if !analysis.HasLeak {
		t.Fatal("expected a goroutine-leak flag given the baseline diff")
	}
}
