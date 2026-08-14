package traefikoidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// =============================================================================
// Helper builders
// =============================================================================

// makeBearerJWT constructs a JWT with explicit header + claims for tests.
// Signature is opaque (b64("signature")) — bearer tests don't exercise the
// real cryptographic verifier; verification is bypassed via tokenCache pre-
// seed so the bearer pipeline under test sees a "verified" token.
func makeBearerJWT(t *testing.T, header, claims map[string]interface{}) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(hb),
		base64.RawURLEncoding.EncodeToString(cb),
		base64.RawURLEncoding.EncodeToString([]byte("signature")),
	)
}

// defaultBearerHeader produces the standard RS256+kid header used in tests.
func defaultBearerHeader() map[string]interface{} {
	return map[string]interface{}{"alg": "RS256", "kid": "test-kid"}
}

// defaultBearerClaims produces a baseline access-token claim set. Tests
// shallow-clone and override fields as needed.
func defaultBearerClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss":   "https://issuer.example.com",
		"aud":   "https://api.example.com",
		"sub":   "service-account-1",
		"scope": "api:read api:write",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
	}
}

// makeBearerOIDC constructs a TraefikOidc wired for bearer auth tests. The
// real verifyTokenWithOpts pipeline is short-circuited via tokenCache pre-
// seed: any token Set into t.tokenCache returns nil from VerifyToken,
// letting tests exercise the post-verify bearer logic (classifier, identifier,
// throttle, header forwarding) without standing up JWKs.
func makeBearerOIDC(t *testing.T, next http.Handler) *TraefikOidc {
	t.Helper()
	sm := createTestSessionManager(t)
	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               sm,
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://issuer.example.com",
		audience:                     "https://api.example.com",
		clientID:                     "https://api.example.com",
		tokenCache:                   NewTokenCache(),
		excludedURLs:                 map[string]struct{}{"/favicon.ico": {}},
		allowedRolesAndGroups:        map[string]struct{}{},
		limiter:                      rate.NewLimiter(rate.Every(time.Second), 1000),
		ctx:                          context.Background(),
		enableBearerAuth:             true,
		stripAuthorizationHeader:     true,
		bearerEmitWWWAuthenticate:    true,
		bearerOverridesCookie:        false,
		bearerIdentifierClaim:        "sub",
		maxIdentifierLength:          256,
		maxTokenAge:                  24 * time.Hour,
		bearerFailureThreshold:       20,
		bearerFailureWindow:          60 * time.Second,
		bearerFailurePenalty:         60 * time.Second,
		bearerFailureTracker:         newBearerFailureTracker(20, 60*time.Second, 60*time.Second),
	}
	oidc.extractClaimsFunc = extractClaims
	close(oidc.initComplete)
	return oidc
}

// seedVerified pre-populates the tokenCache so verifyTokenWithOpts short-
// circuits to nil for the given token. Mirrors the production fast-return
// path at token_manager.go for previously-verified tokens.
func seedVerified(t *testing.T, oidc *TraefikOidc, token string, claims map[string]interface{}) {
	t.Helper()
	if oidc.tokenCache == nil {
		oidc.tokenCache = NewTokenCache()
	}
	oidc.tokenCache.Set(token, claims, time.Hour)
}

// =============================================================================
// Unit tests — small helpers
// =============================================================================

func TestDetectBearerToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"missing header", "", "", false},
		{"basic auth", "Basic abc", "", false},
		{"bearer with token", "Bearer abc.def.ghi", "abc.def.ghi", true},
		{"lowercase bearer", "bearer abc.def.ghi", "abc.def.ghi", true},
		{"mixed case", "BeArEr abc.def.ghi", "abc.def.ghi", true},
		{"empty token after prefix", "Bearer    ", "", false},
		{"bearer no space", "Bearerabc", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got, ok := detectBearerToken(req)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("got=(%q, %v), want=(%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestParseBearerJOSEHeader(t *testing.T) {
	t.Parallel()
	mk := func(t *testing.T, h map[string]interface{}) string {
		return makeBearerJWT(t, h, map[string]interface{}{"sub": "x"})
	}
	cases := []struct {
		header  map[string]interface{}
		name    string
		wantErr bool
	}{
		{name: "valid RS256", header: map[string]interface{}{"alg": "RS256", "kid": "k1"}, wantErr: false},
		{name: "valid ES512", header: map[string]interface{}{"alg": "ES512", "kid": "abc-_.="}, wantErr: false},
		{name: "alg=none rejected", header: map[string]interface{}{"alg": "none", "kid": "k1"}, wantErr: true},
		{name: "alg=HS256 rejected", header: map[string]interface{}{"alg": "HS256", "kid": "k1"}, wantErr: true},
		{name: "missing kid", header: map[string]interface{}{"alg": "RS256"}, wantErr: true},
		{name: "kid too long", header: map[string]interface{}{"alg": "RS256", "kid": strings.Repeat("a", bearerKidMaxLen+1)}, wantErr: true},
		{name: "kid bad chars", header: map[string]interface{}{"alg": "RS256", "kid": "evil/../etc/passwd"}, wantErr: true},
		{name: "kid with space", header: map[string]interface{}{"alg": "RS256", "kid": "key one"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := mk(t, tc.header)
			err := parseBearerJOSEHeader(token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestSanitiseBearerIdentifier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"normal sub", "service-account-1", "service-account-1", false},
		{"email-like", "alice@example.com", "alice@example.com", false},
		{"trim whitespace", "  abc  ", "abc", false},
		{"empty", "", "", true},
		{"only whitespace", "   ", "", true},
		{"control char (newline)", "alice\nbob", "", true},
		{"control char (CR)", "alice\rbob", "", true},
		{"control char (NUL)", "alice\x00bob", "", true},
		{"bidi override", "alice\u202ebob", "", true},
		{"bidi isolate", "alice\u2066bob", "", true},
		{"comma delimiter", "alice,bob", "", true},
		{"semicolon delimiter", "alice;bob", "", true},
		{"equals delimiter", "alice=bob", "", true},
		{"over length", strings.Repeat("a", 257), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sanitizeBearerIdentifier(tc.in, 256)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestResolveBearerIdentifier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		claims  map[string]interface{}
		name    string
		claim   string
		want    string
		wantErr bool
	}{
		{name: "default sub", claims: map[string]interface{}{"sub": "abc"}, claim: "", want: "abc"},
		{name: "explicit sub", claims: map[string]interface{}{"sub": "abc"}, claim: "sub", want: "abc"},
		{name: "custom client_id claim", claims: map[string]interface{}{"client_id": "svc"}, claim: "client_id", want: "svc"},
		{name: "missing claim", claims: map[string]interface{}{"other": "x"}, claim: "sub", wantErr: true},
		{name: "numeric claim", claims: map[string]interface{}{"sub": 123}, claim: "sub", want: "123"}, // R102: scalar numbers stringified, not rejected
		{name: "object claim", claims: map[string]interface{}{"sub": map[string]interface{}{"a": 1}}, claim: "sub", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBearerIdentifier(tc.claims, tc.claim)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestEnforceMultiAudienceAzp(t *testing.T) {
	t.Parallel()
	const cid = "https://api.example.com"
	cases := []struct {
		claims  map[string]interface{}
		name    string
		wantErr bool
	}{
		{name: "single string aud", claims: map[string]interface{}{"aud": "x"}, wantErr: false},
		{name: "single element array", claims: map[string]interface{}{"aud": []interface{}{"x"}}, wantErr: false},
		{name: "multi-aud with matching azp", claims: map[string]interface{}{"aud": []interface{}{"a", "b"}, "azp": cid}, wantErr: false},
		{name: "multi-aud missing azp", claims: map[string]interface{}{"aud": []interface{}{"a", "b"}}, wantErr: true},
		{name: "multi-aud empty azp", claims: map[string]interface{}{"aud": []interface{}{"a", "b"}, "azp": ""}, wantErr: true},
		{name: "multi-aud wrong azp", claims: map[string]interface{}{"aud": []interface{}{"a", "b"}, "azp": "other"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceMultiAudienceAzp(tc.claims, cid)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestEnforceIatAge(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cases := []struct {
		name    string
		iat     float64
		maxAge  time.Duration
		wantErr bool
	}{
		{name: "fresh", iat: float64(now.Unix()), maxAge: time.Hour, wantErr: false},
		{name: "23h59m old, max 24h", iat: float64(now.Add(-23*time.Hour - 59*time.Minute).Unix()), maxAge: 24 * time.Hour, wantErr: false},
		{name: "25h old, max 24h", iat: float64(now.Add(-25 * time.Hour).Unix()), maxAge: 24 * time.Hour, wantErr: true},
		{name: "1970 token", iat: float64(0), maxAge: 24 * time.Hour, wantErr: true},
		{name: "maxAge disabled (0)", iat: float64(0), maxAge: 0, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceIatAge(map[string]interface{}{"iat": tc.iat}, tc.maxAge)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestBearerFailureTracker(t *testing.T) {
	t.Parallel()
	tr := newBearerFailureTracker(3, 60*time.Second, 60*time.Second)
	const ip = "10.0.0.1"
	// Below threshold: not blocked.
	for i := 0; i < 2; i++ {
		tr.recordFailure(ip)
		if b, _ := tr.blocked(ip); b {
			t.Fatalf("blocked too early after %d failures", i+1)
		}
	}
	// Threshold reached: blocked.
	tr.recordFailure(ip)
	if b, retry := tr.blocked(ip); !b || retry <= 0 {
		t.Fatalf("expected blocked with positive retry, got=%v retry=%v", b, retry)
	}
	// A success while a penalty is active must NOT wipe the in-effect lockout
	// (otherwise a single success could clear an attacker's penalty).
	tr.recordSuccess(ip)
	if b, _ := tr.blocked(ip); !b {
		t.Fatalf("expected still blocked after success while penalty active")
	}
	// Other IPs are unaffected.
	if b, _ := tr.blocked("10.0.0.2"); b {
		t.Fatalf("unrelated IP should not be blocked")
	}

	// With an expired penalty, a success resets the counter so a subsequent
	// sub-threshold failure does not immediately re-block.
	tr2 := newBearerFailureTracker(3, 60*time.Second, 1*time.Millisecond)
	const ip2 = "10.0.0.3"
	for i := 0; i < 3; i++ {
		tr2.recordFailure(ip2)
	}
	time.Sleep(5 * time.Millisecond) // let the short penalty expire
	if b, _ := tr2.blocked(ip2); b {
		t.Fatalf("expected unblocked after penalty expiry")
	}
	tr2.recordSuccess(ip2) // resets count since penalty has passed
	tr2.recordFailure(ip2) // single failure, well below threshold
	if b, _ := tr2.blocked(ip2); b {
		t.Fatalf("expected unblocked: counter should have reset after success")
	}
}

// =============================================================================
// Integration tests — full ServeHTTP via the bearer pipeline
// =============================================================================

func TestServeHTTP_Bearer_HappyPath(t *testing.T) {
	t.Parallel()
	var nextCalled atomic.Bool
	var capturedHeaders http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled.Store(true)
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if !nextCalled.Load() {
		t.Fatalf("expected next handler to run; got status=%d body=%q", rw.Code, rw.Body.String())
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rw.Code)
	}
	if got := capturedHeaders.Get("X-Forwarded-User"); got != "service-account-1" {
		t.Fatalf("X-Forwarded-User=%q, want service-account-1", got)
	}
	if got := capturedHeaders.Get("Authorization"); got != "" {
		t.Fatalf("Authorization should be stripped, got=%q", got)
	}
}

func TestServeHTTP_Bearer_StripAuthDisabled(t *testing.T) {
	t.Parallel()
	var capturedAuth string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	oidc.stripAuthorizationHeader = false
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if !strings.HasPrefix(capturedAuth, "Bearer ") {
		t.Fatalf("expected Authorization to be forwarded, got=%q", capturedAuth)
	}
}

func TestServeHTTP_Bearer_RejectIDToken(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for ID token rejection")
	})
	oidc := makeBearerOIDC(t, next)
	// ID-token shape: nonce claim present and no scope. detectTokenType
	// returns true.
	claims := map[string]interface{}{
		"iss":   "https://issuer.example.com",
		"aud":   "https://api.example.com",
		"sub":   "user-1",
		"nonce": "n-0S6_WzA2Mj",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
	}
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
	if wa := rw.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `error="invalid_token"`) {
		t.Fatalf("expected WWW-Authenticate invalid_token, got=%q", wa)
	}
}

func TestServeHTTP_Bearer_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for alg=none")
	})
	oidc := makeBearerOIDC(t, next)
	header := map[string]interface{}{"alg": "none", "kid": "k1"}
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, header, claims)
	// Even if we pre-seeded the cache, the early alg pin runs FIRST.
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_KidTooLongRejected(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for oversized kid")
	})
	oidc := makeBearerOIDC(t, next)
	header := map[string]interface{}{"alg": "RS256", "kid": strings.Repeat("a", bearerKidMaxLen+1)}
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, header, claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_MultiAudRequiresAzp(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for multi-aud without azp")
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	claims["aud"] = []interface{}{"https://api.example.com", "https://other.example.com"}
	delete(claims, "azp")
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_MultiAudWithAzpAccepted(t *testing.T) {
	t.Parallel()
	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	claims["aud"] = []interface{}{"https://api.example.com", "https://other.example.com"}
	claims["azp"] = oidc.clientID
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK || !nextCalled.Load() {
		t.Fatalf("expected 200 + next called; got status=%d called=%v", rw.Code, nextCalled.Load())
	}
}

func TestServeHTTP_Bearer_IatTooOldRejected(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for old iat")
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	claims["iat"] = float64(time.Now().Add(-25 * time.Hour).Unix())
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_IdentifierWithBidiRejected(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for bidi identifier")
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	claims["sub"] = "alice\u202ebob"
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_ReplayRegression(t *testing.T) {
	t.Parallel()
	var successCount atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		successCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	claims["jti"] = "regression-jti"
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/api/work", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rw := httptest.NewRecorder()
		oidc.ServeHTTP(rw, req)
		if rw.Code != http.StatusOK {
			t.Fatalf("iteration %d: status=%d, want 200", i, rw.Code)
		}
	}
	if successCount.Load() != 100 {
		t.Fatalf("successCount=%d, want 100", successCount.Load())
	}
}

func TestServeHTTP_Bearer_ThrottleTrips429(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run during throttle test")
	})
	oidc := makeBearerOIDC(t, next)
	oidc.bearerFailureTracker = newBearerFailureTracker(3, 60*time.Second, 60*time.Second)

	// Send malformed bearers from the same RemoteAddr until threshold trips.
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/work", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("Authorization", "Bearer not-a-jwt")
		rw := httptest.NewRecorder()
		oidc.ServeHTTP(rw, req)
		return rw
	}
	for i := 0; i < 3; i++ {
		rw := send()
		if rw.Code != http.StatusUnauthorized {
			t.Fatalf("pre-throttle iteration %d: status=%d, want 401", i, rw.Code)
		}
	}
	// 4th request: throttled.
	rw := send()
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after threshold, got %d", rw.Code)
	}
	if ra := rw.Header().Get("Retry-After"); ra == "" {
		t.Fatalf("expected Retry-After header on 429")
	}
}

func TestServeHTTP_Bearer_Introspection503_NotThrottleFailure(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run: introspection 503 should reject request")
	})
	oidc := makeBearerOIDC(t, next)
	oidc.requireTokenIntrospection = true
	// Unreachable introspection endpoint -> every request returns 503.
	oidc.introspectionURL = "http://127.0.0.1:1/"
	oidc.httpClient = &http.Client{Timeout: 500 * time.Millisecond}
	oidc.bearerFailureTracker = newBearerFailureTracker(3, 60*time.Second, 60*time.Second)

	claims := defaultBearerClaims()
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/work", nil)
		req.RemoteAddr = "10.0.0.7:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		rw := httptest.NewRecorder()
		oidc.ServeHTTP(rw, req)
		return rw
	}

	// Four requests during an introspection outage. Each is a 503 and the
	// per-IP failure count must stay at 0 so the threshold (3) never trips.
	// On OLD code each 503 was counted as a throttle failure, so the 4th
	// request would come back 429 (penalty box) instead of 503.
	for i := 0; i < 4; i++ {
		rw := send()
		if rw.Code != http.StatusServiceUnavailable {
			t.Fatalf("iteration %d: status=%d, want %d", i, rw.Code, http.StatusServiceUnavailable)
		}
	}
}

func TestServeHTTP_Bearer_ExcludedURLStripsAuth(t *testing.T) {
	t.Parallel()
	var capturedAuth string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	oidc.excludedURLs = map[string]struct{}{"/favicon.ico": {}}

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	req.Header.Set("Authorization", "Bearer abc.def.ghi")
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("excluded path should pass; got %d", rw.Code)
	}
	if capturedAuth != "" {
		t.Fatalf("Authorization must be stripped on excluded paths, got=%q", capturedAuth)
	}
}

func TestServeHTTP_Bearer_RolesGate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		rolesClaim []interface{}
		want       int
	}{
		{name: "matching role", rolesClaim: []interface{}{"admin"}, want: http.StatusOK},
		{name: "no matching role", rolesClaim: []interface{}{"viewer"}, want: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			oidc := makeBearerOIDC(t, next)
			oidc.allowedRolesAndGroups = map[string]struct{}{"admin": {}}
			oidc.roleClaimName = "roles"
			claims := defaultBearerClaims()
			claims["roles"] = tc.rolesClaim
			token := makeBearerJWT(t, defaultBearerHeader(), claims)
			seedVerified(t, oidc, token, claims)

			req := httptest.NewRequest("GET", "/api/work", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rw := httptest.NewRecorder()
			oidc.ServeHTTP(rw, req)
			if rw.Code != tc.want {
				t.Fatalf("status=%d, want %d", rw.Code, tc.want)
			}
		})
	}
}

func TestServeHTTP_Bearer_CookieWinsByDefault(t *testing.T) {
	t.Parallel()
	// Both cookie and bearer present: cookie path runs (which will redirect
	// to /authorize since the cookie is empty/unauthenticated).
	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	prefix := oidc.sessionManager.GetCookiePrefix()
	req.AddCookie(&http.Cookie{Name: prefix + "main", Value: "irrelevant"})
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	// Cookie path consumed the request; bearer was ignored. Since the
	// cookie is empty, the cookie path will either 302 to /authorize or
	// return 401 — in either case, next must NOT be called.
	if nextCalled.Load() {
		t.Fatalf("next must not be called when bearer is ignored due to cookie precedence")
	}
}

func TestServeHTTP_Bearer_BearerOverridesCookie(t *testing.T) {
	t.Parallel()
	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	oidc.bearerOverridesCookie = true
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	prefix := oidc.sessionManager.GetCookiePrefix()
	req.AddCookie(&http.Cookie{Name: prefix + "main", Value: "irrelevant"})
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if !nextCalled.Load() || rw.Code != http.StatusOK {
		t.Fatalf("expected bearer to win with override; status=%d called=%v", rw.Code, nextCalled.Load())
	}
}

func TestServeHTTP_Bearer_OversizedToken(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for oversized token")
	})
	oidc := makeBearerOIDC(t, next)
	huge := strings.Repeat("a", AccessTokenConfig.MaxLength+1)
	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+huge)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_MalformedJWT(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not run for malformed JWT")
	})
	oidc := makeBearerOIDC(t, next)
	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer not.jwt") // 1 dot
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rw.Code)
	}
}

func TestServeHTTP_Bearer_FeatureOffPassesThrough(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not be reached: cookie path runs and (with no session)
		// will redirect or 401. We assert no panic / next not called.
		t.Fatalf("next must not run when bearer is off and no valid session exists")
	})
	oidc := makeBearerOIDC(t, next)
	oidc.enableBearerAuth = false
	claims := defaultBearerClaims()
	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)
	req := httptest.NewRequest("GET", "/api/work", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)
	// Expect non-200: either 302 to /authorize or 401. The point is the
	// bearer pipeline didn't run.
	if rw.Code == http.StatusOK {
		t.Fatalf("expected non-200 when bearer is off; got %d", rw.Code)
	}
}

// =============================================================================
// Startup validation tests
// =============================================================================

func TestStartupValidation_BearerRequiresAudience(t *testing.T) {
	t.Parallel()
	cfg := CreateConfig()
	cfg.ProviderURL = "https://issuer.example.com"
	cfg.ClientID = "id"
	cfg.ClientSecret = "secret"
	cfg.CallbackURL = "/oauth/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.EnableBearerAuth = true
	cfg.Audience = ""
	_, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "bearer-test")
	if err == nil || !strings.Contains(err.Error(), "requires Audience") {
		t.Fatalf("expected audience-required error, got %v", err)
	}
}

func TestStartupValidation_BearerRejectsEmailIdentifier(t *testing.T) {
	t.Parallel()
	cfg := CreateConfig()
	cfg.ProviderURL = "https://issuer.example.com"
	cfg.ClientID = "id"
	cfg.ClientSecret = "secret"
	cfg.CallbackURL = "/oauth/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.EnableBearerAuth = true
	cfg.Audience = "https://api.example.com"
	cfg.BearerIdentifierClaim = "email"
	_, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "bearer-test")
	if err == nil || !strings.Contains(err.Error(), "bearerIdentifierClaim=\"email\"") {
		t.Fatalf("expected email-identifier rejection, got %v", err)
	}
}

// =============================================================================
// Principal invariants
// =============================================================================

func TestBuildPrincipalFromSession_NoIdentifier(t *testing.T) {
	t.Parallel()
	oidc := &TraefikOidc{logger: NewLogger("error")}
	if p := oidc.buildPrincipalFromSession(nil); p != nil {
		t.Fatalf("nil session must produce nil principal")
	}
}
