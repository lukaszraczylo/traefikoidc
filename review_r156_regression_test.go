package traefikoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// R156 review-round regressions.

// TestR156_Introspection4xxForcesRefresh guards the introspection status
// fix (token_introspection.go + token_validation_rs.go). A definitive
// 4xx from the introspection endpoint (e.g. 401 for an unknown or
// revoked opaque access token) used to be flattened into a plain error,
// so validateStandardTokensRS substring-matching ("token is not
// active"/"revoked"/"token has expired") treated it as a TRANSIENT
// failure and — with requireTokenIntrospection off — fell through to
// ID-token-only auth, authenticating a revoked opaque access token
// instead of refreshing. The fix carries the HTTP status in a typed
// *HTTPError and treats 4xx as token-invalid.
// Fail-on-old: the 4xx is classed as transient, so with a valid
// idToken present the fall-through ID-token validation returns no
// refresh (shouldRefresh=false); the fixed code returns shouldRefresh.
func TestR156_Introspection4xxForcesRefresh(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnauthorized) // definite: token unknown/revoked
	}))
	defer ts.Close()

	// A non-empty idToken that the fall-through ID-token validation sees as
	// valid (unexpired) — so OLD code authenticates instead of refreshing.
	const idToken = "dummy-but-cached-id-token"
	tc := NewTokenCache()
	tc.Set(idToken, map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}, time.Hour)

	tObj := &TraefikOidc{
		logger:                    GetSingletonNoOpLogger(),
		introspectionURL:          ts.URL,
		httpClient:                ts.Client(),
		allowOpaqueTokens:         true,
		requireTokenIntrospection: false,
		tokenCache:                tc,
		clientID:                  "test-client",
		clientSecret:              "test-secret",
	}

	rs := &requestState{
		authenticated: true,
		accessToken:   "OpaqueNotARealJwt-1234567890", // dotCount != 2 -> opaque path
		refreshToken:  "refresh-token-value",
		idToken:       idToken,
	}

	_, shouldRefresh, _ := tObj.validateStandardTokensRS(rs)
	if !shouldRefresh {
		t.Error("4xx from introspection must be treated as token-invalid and trigger refresh; got no refresh (authenticated via ID-token fall-through)")
	}
}

// TestR156_IntrospectionAcceptsBearerTokenType guards the token_type fix
// (token_introspection.go + bearer_auth.go). RFC 7662's token_type is
// the RFC 6749 token type, whose value for an access token is "Bearer"
// (RFC 6750). The check only accepted "access_token", so a conforming
// provider returning token_type="Bearer" had every valid token rejected.
// Fail-on-old: validateOpaqueToken rejects token_type="Bearer".
func TestR156_IntrospectionAcceptsBearerTokenType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":     true,
			"token_type": "Bearer",
			"exp":        time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer ts.Close()

	tObj := &TraefikOidc{
		logger:            GetSingletonNoOpLogger(),
		introspectionURL:  ts.URL,
		httpClient:        ts.Client(),
		allowOpaqueTokens: true,
	}

	if err := tObj.validateOpaqueToken("some-opaque-token"); err != nil {
		t.Errorf("conforming provider with token_type \"Bearer\" must be accepted; got error: %v", err)
	}
}

// TestR156_ReplayFallbackNoSelfDeadlock guards the jwt.go replay-fallback
// fix. When a concurrent cleanupReplayCache nils shardedReplayCache in
// the window after initReplayCache (which re-creates a nil cache) but
// before the guarded read, JWT.Verify takes the legacy fallback branch,
// which used to call replayCacheMu.Lock() while still holding
// replayCacheMu.RLock() — a non-reentrant RWMutex self-deadlock — and
// then called replayCache.Get before its nil-check (nil-panic). The fix
// releases the read lock before taking the write lock and guards the
// legacy cache for nil.
//
// The fallback is only reachable under that concurrency race, so this is
// a best-effort regression: run cleanup in a tight loop alongside a
// stream of fresh Verifies, bounding each with a timeout so a
// reintroduced deadlock fails the test rather than hanging the suite.
func TestR156_ReplayFallbackNoSelfDeadlock(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				cleanupReplayCache()
			}
		}
	}()

	defer func() {
		close(stop)
		wg.Wait()
		// Leave the replay caches in a functional state and unbind any
		// (possibly deadlocked) stale lock so later tests are unaffected.
		initReplayCache()
	}()

	const verifies = 1500
	for i := 0; i < verifies; i++ {
		raw, err := createTestJWT(key, "RS256", "k", map[string]interface{}{
			"iss": "https://provider.example.com",
			"aud": "test-aud",
			"sub": "test-user",
			"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
			"jti": fmt.Sprintf("fresh-jti-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseJWT(raw)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func(j *JWT) { done <- j.Verify("https://provider.example.com", "test-aud") }(parsed)

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("unexpected verify error: %v", err)
			}
		case <-time.After(400 * time.Millisecond):
			t.Fatal("Verify hung: replay-fallback self-deadlock still present")
		}
	}
}
