package traefikoidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestIntrospectToken_NegativeResultNotCached regresses R104: an inactive
// (revoked) introspection result was cached for the full TTL (5min; 30s
// when required), so if the provider re-issued a token with the same
// string within that window, the middleware kept rejecting it on the stale
// negative entry. Inactive results are now re-introspected on each
// request; only active results are cached.
func TestIntrospectToken_NegativeResultNotCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		// First call: provider reports revoked. Second: token re-issued, now active.
		_ = json.NewEncoder(w).Encode(map[string]any{"active": n > 1})
	}))
	defer srv.Close()

	oidc := &TraefikOidc{
		providerURL:        "https://provider.example.com",
		logger:             NewLogger("error"),
		clientID:           "test-client",
		clientSecret:       "test-secret",
		httpClient:         http.DefaultClient,
		introspectionCache: NewCache(),
	}
	metadata := &ProviderMetadata{
		Issuer:   "https://provider.example.com",
		AuthURL:  "https://provider.example.com/authorize",
		TokenURL: "https://provider.example.com/token",
		JWKSURL:  "https://provider.example.com/jwks",
	}
	// configIntrospectionURL (unlike discovery) needs no same-host pin; it is
	// at the same trust tier as providerURL (see issue152 test above).
	oidc.configIntrospectionURL = srv.URL
	oidc.updateMetadataEndpoints(metadata)

	first, err := oidc.introspectToken("tok")
	if err != nil {
		t.Fatalf("first introspectToken: %v", err)
	}
	if first.Active {
		t.Fatal("first introspection result must be inactive")
	}

	second, err := oidc.introspectToken("tok")
	if err != nil {
		t.Fatalf("second introspectToken: %v", err)
	}
	if !second.Active {
		t.Fatal("re-issued token (2nd call) must be re-introspected, not served from a stale negative cache entry")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("introspection endpoint hits = %d, want 2 (negative result must not be cached)", got)
	}
}

// TestRefreshToken_IdentityNotSubstituted regresses R106: refreshToken
// adopted the refreshed ID token's user identifier without comparing it to
// the identity the session already holds (granted at callback after email
// gate + isAllowedUser). A refreshed token carrying a different subject
// must not silently substitute the user mid-session; the refresh is
// aborted and the original identity preserved.
func TestRefreshToken_IdentityNotSubstituted(t *testing.T) {
	testLogger := newNoOpLogger()

	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		testLogger,
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	oidc := &TraefikOidc{
		logger:        testLogger,
		tokenVerifier: &EnhancedMockTokenVerifier{Err: nil},
		extractClaimsFunc: func(token string) (map[string]interface{}, error) {
			// Refreshed token claims a DIFFERENT email than the session holds.
			return map[string]interface{}{"email": "other@example.com", "sub": "orig-sub"}, nil
		},
		userIdentifierClaim: "email",
		tokenExchanger: &EnhancedMockTokenExchanger{
			RefreshTokenFunc: func(rt string) (*TokenResponse, error) {
				return &TokenResponse{IDToken: "valid-idtoken", AccessToken: "new-access-token"}, nil
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	defer session.returnToPoolSafely()
	session.SetRefreshToken("refresh-token")
	session.SetAccessToken("old-access-token-value-abcdefghij")
	session.SetUserIdentifier("original@example.com")

	// OLD behavior: refresh returns true and overwrites the session
	// identifier with the refreshed token's ("other@example.com"). NEW: the
	// differing identity aborts the refresh and preserves the original.
	oidc.refreshToken(rw, req, session)
	if got := session.GetUserIdentifier(); got != "original@example.com" {
		t.Fatalf("refresh substituted the session identity; got %q, want original@example.com", got)
	}
}

// TestExecuteTokenOperation_RetryInsideBreaker regresses R106: retry was
// composed OUTSIDE the circuit breaker, so each retry attempt recorded a
// breaker failure and maxFailures(3) + maxAttempts(3) meant one logical
// token operation during a brief outage opened the breaker, failing the
// very next genuine request. Retry is now the inner layer, breaker the
// outer layer: one logical op counts as ONE breaker observation.
func TestExecuteTokenOperation_RetryInsideBreaker(t *testing.T) {
	logger := newNoOpLogger()
	manager := NewTokenResilienceManager(DefaultTokenResilienceConfig(), logger)

	var calls int32
	_ = manager.ExecuteTokenOperation(context.Background(), "test", false, func() error {
		atomic.AddInt32(&calls, 1)
		return errors.New("connection refused") // retryable
	})

	if got := manager.circuitBreaker.GetState(); got != CircuitBreakerClosed {
		t.Fatalf("breaker state = %v, want closed (one logical op with internal retries must count as one aggregate observation)", got)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("operation was never attempted")
	}
}

// TestRecoveryPath_NoSessionUseAfterReturn regresses R108: the session
// recovery path (corrupted cookie) called session.Clear(), which returns the
// session to the object pool, then kept using the same pointer in
// defaultInitiateAuthentication. A concurrent GetSession could acquire that
// pooled object and both requests would write to one shared session (data
// race / cross-request session bleed). The fix drops the pointer after
// Clear and mints a fresh owned session. Run with -race.
func TestRecoveryPath_NoSessionUseAfterReturn(t *testing.T) {
	oidc := &TraefikOidc{
		next:                         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		logger:                       newNoOpLogger(),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
		redirURLPath:                 "/callback",
		logoutURLPath:                "/logout",
		clientID:                     "test-client",
		audience:                     "test-client",
		authURL:                      "https://provider.example.com/auth",
	}
	close(oidc.initComplete)

	// Corrupted session cookie forces the recovery path (GetSession errors).
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.AddCookie(&http.Cookie{Name: "_oidc_session", Value: "corrupted!!!invalid!!!"})

	// Concurrently acquire sessions so the pool can hand the cleared session
	// to another owner while the recovery path (mis)uses it.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s, err := oidc.sessionManager.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
				if err == nil && s != nil {
					s.returnToPoolSafely()
				}
			}
		}()
	}

	for i := 0; i < 500; i++ {
		rw := httptest.NewRecorder()
		oidc.ServeHTTP(rw, req)
		if rw.Code != http.StatusFound && rw.Code != http.StatusSeeOther {
			t.Fatalf("recovery iter %d: expected auth redirect, got %d", i, rw.Code)
		}
	}
	close(stop)
	wg.Wait()
}

// TestSessionClearThenReacquire_AliasesRootcause is a deterministic
// root-cause companion to TestRecoveryPath_NoSessionUseAfterReturn (R108).
// Session.Clear() returns the object to the pool; the very next GetSession
// in the same goroutine hands back the SAME object. So holding onto the
// pointer after Clear and continuing to mutate it (as the old recovery path
// did) is a use-after-return — the object is concurrently owned by the new
// GetSession holder, and writes through either alias bleed across requests.
func TestSessionClearThenReacquire_AliasesRootcause(t *testing.T) {
	sm := createTestSessionManager(t)
	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	s.SetUserIdentifier("original")

	if err := s.Clear(req, rec); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	// After Clear the object is pooled again...
	if s.inUse.Load() {
		t.Fatalf("cleared session must be free (pooled) again, but is still marked in use")
	}

	// ...and the next GetSession in this goroutine reuses it (sync.Pool
	// LIFO per-P). This is exactly why the recovery path must not keep
	// using `s` after Clear: `s2` is the same object, now owned by a
	// different logical holder.
	s2, err := sm.GetSession(httptest.NewRequest(http.MethodGet, "/b", nil))
	if err != nil {
		t.Fatalf("GetSession(reacquire): %v", err)
	}
	defer s2.returnToPoolSafely()
	if s != s2 {
		t.Logf("pool did not reuse the cleared session in this goroutine; the aliasing hazard is manager-dependent, but the recovery path must still mint a fresh session")
		return
	}
	if !s2.inUse.Load() {
		t.Fatalf("reacquired session must be marked in use")
	}
	if !s.inUse.Load() {
		t.Fatalf("the alias, if it were still held by the recovery flow, must reflect ownership — proving reuse-after-Clear would alias two owners")
	}
	// Writes through one alias are visible via the other — cross-request bleed.
	s2.SetUserIdentifier("other")
	if got := s.GetUserIdentifier(); got != "other" {
		t.Fatalf("aliased object: write via reacquired holder must be visible via the stale pointer, got %q", got)
	}
}

// TestStringListFromClaim_NumericItemsStringified regresses R105: the
// []interface{} branch of stringListFromClaim dropped non-string group/role
// items, so a numeric group produced an empty list (403 / missing
// X-User-Groups) with no signal. Scalar items are now stringified via
// claimScalarString, matching the R102 numeric-tolerance precedent for
// identifier claims.
func TestStringListFromClaim_NumericItemsStringified(t *testing.T) {
	got, ok := stringListFromClaim([]interface{}{"admin", json.Number("123"), map[string]interface{}{"k": "v"}})
	if !ok {
		t.Fatal("stringListFromClaim must accept a []interface{} seed")
	}
	want := []string{"admin", "123"}
	if len(got) != len(want) {
		t.Fatalf("stringListFromClaim = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stringListFromClaim = %v, want %v", got, want)
		}
	}
}

// TestValidateChunkingEfficiency_NoRejectOnDecompressed regresses R104: the
// read path runs validateChunkingEfficiency on the *decompressed* token,
// and its hard chunk-count rejection (> MaxChunks) permanently rejected a
// large access token that was legitimately stored compressed (whose
// decompressed length exceeds MaxChunks*MaxChunkSize), forcing re-auth on
// every request. The read-side check is now advisory only; the actual
// budget is enforced at write time on the stored (compressed) form.
func TestValidateChunkingEfficiency_NoRejectOnDecompressed(t *testing.T) {
	cm := &ChunkManager{logger: NewLogger("")}
	config := TokenConfig{Type: "access", MaxChunks: 50, MaxChunkSize: 1400}
	// 71001 bytes > 50*1400 (throws the old >MaxChunks rejection) yet is a
	// valid decompressed length the size-aware validator would accept. It no
	// longer returns an error (only logs an optimization hint), so a
	// large-but-safely-stored token must assemble on the read path rather
	// than being hard-rejected.
	big := strings.Repeat("a", 71001)
	cm.validateChunkingEfficiency(big, config) // must not reject / must not panic
}
