package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestServeHTTP_ExcludedURL_StripsIdentityHeaders regresses excluded-URL
// (public path) bypass forwarding client-forged identity headers to the
// backend. forwardAuthorized and the SSE/WebSocket bypass both strip the
// owned identity headers so token-derived values are authoritative; the
// excluded branch forwarded t.next.ServeHTTP without clearing them, so a
// client could put X-Forwarded-User: admin on a public path (health,
// metrics) and the backend would trust it (R102).
func TestServeHTTP_ExcludedURL_StripsIdentityHeaders(t *testing.T) {
	excluded := map[string]struct{}{"/health": {}}

	var forwarded http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		excludedURLs:                 excluded,
		next:                         next,
		logger:                       NewLogger("debug"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
	}
	close(oidc.initComplete)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Forwarded-User", "forged-admin")
	req.Header.Set("X-User-Groups", "forged-admins")
	req.Header.Set("X-User-Roles", "forged-super")
	req.Header.Set("X-Auth-Request-Token", "forged-token")
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	for _, h := range identityHeaders {
		if v := forwarded.Get(h); v != "" {
			t.Errorf("header %q = %q reached backend through excluded URL; want empty (forged value)", h, v)
		}
	}
}

type recordingCache struct {
	mu   sync.Mutex
	ttls map[string]time.Duration
}

func (r *recordingCache) Set(k string, v any, ttl time.Duration) {
	r.mu.Lock()
	r.ttls[k] = ttl
	r.mu.Unlock()
}
func (r *recordingCache) Get(k string) (any, bool) { return nil, false }
func (r *recordingCache) Delete(k string)          {}
func (r *recordingCache) SetMaxSize(int)           {}
func (r *recordingCache) Size() int                { return 0 }
func (r *recordingCache) Clear()                   {}
func (r *recordingCache) Cleanup()                 {}
func (r *recordingCache) Close()                   {}
func (r *recordingCache) GetStats() map[string]any { return nil }

func makeJWTForTest(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

// TestRevokeToken_BlacklistDurationCoversTokenExp regresses RevokeToken
// hardcoding a 24h blacklist TTL and ignoring the token's exp claim. A
// revoked token stays cryptographically valid until exp, so with exp > 24h
// away it became re-presentable (and re-cacheable) after 24h. The
// blacklist TTL must extend to cover the token's full validity window.
func TestRevokeToken_BlacklistDurationCoversTokenExp(t *testing.T) {
	bl := &recordingCache{ttls: map[string]time.Duration{}}
	oidc := &TraefikOidc{tokenBlacklist: bl, tokenCache: NewTokenCache(), logger: NewLogger("debug")}

	// Long-lived token: exp 72h away. Blacklist must outlast 24h for both
	// the raw token and its jti.
	now := time.Now()
	longToken := makeJWTForTest(map[string]any{"exp": float64(now.Add(72 * time.Hour).Unix()), "jti": "jt-long"})
	oidc.RevokeToken(longToken)
	if d := bl.ttls[longToken]; d <= 24*time.Hour {
		t.Fatalf("blacklist TTL for exp=72h token = %v, want > 24h", d)
	}
	if d := bl.ttls["jt-long"]; d <= 24*time.Hour {
		t.Fatalf("blacklist TTL for jti of exp=72h token = %v, want > 24h", d)
	}

	// Token already expiring soon: 24h floor still covers it.
	shortToken := makeJWTForTest(map[string]any{"exp": float64(now.Add(6 * time.Hour).Unix())})
	oidc.RevokeToken(shortToken)
	if d := bl.ttls[shortToken]; d < 24*time.Hour {
		t.Fatalf("blacklist TTL for exp=6h token = %v, want >= 24h floor", d)
	}
}

// TestClaimScalarString regresses user-identifier extraction doing a strict
// .(string) assertion so a numeric identifier claim (e.g. a numeric sub
// from a non-conformant IdP) was silently dropped -> spurious 500/401 for
// an otherwise valid principal. Scalar numbers are now coerced to their
// decimal string form; non-scalars stay invalid.
func TestClaimScalarString(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
		ok   bool
	}{
		{name: "string", in: "user@example.com", want: "user@example.com", ok: true},
		{name: "empty string", in: "", want: "", ok: true},
		{name: "float64", in: float64(123456), want: "123456", ok: true},
		{name: "json.Number", in: json.Number("987654"), want: "987654", ok: true},
		{name: "int", in: 42, want: "42", ok: true},
		{name: "int64", in: int64(777), want: "777", ok: true},
		{name: "map", in: map[string]any{"x": 1}, want: "", ok: false},
		{name: "slice", in: []any{"a"}, want: "", ok: false},
		{name: "nil", in: nil, want: "", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := claimScalarString(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("claimScalarString(%v) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestResolveBearerIdentifier_NumericClaim regresses the bearer path
// rejecting a numeric identifier claim with 'not a string' -> 401 for a
// valid principal. A numeric sub is now stringified and accepted.
func TestResolveBearerIdentifier_NumericClaim(t *testing.T) {
	oidc := &TraefikOidc{logger: NewLogger("debug")}
	var _ = oidc

	id, berr := resolveBearerIdentifier(map[string]any{"sub": float64(424242)}, "sub")
	if berr != nil {
		t.Fatalf("numeric sub should be accepted, got error: %v", berr.reason)
	}
	if id != "424242" {
		t.Fatalf("numeric sub = %q, want 424242", id)
	}

	// non-scalar still rejected
	if _, berr := resolveBearerIdentifier(map[string]any{"sub": map[string]any{"a": 1}}, "sub"); berr == nil {
		t.Fatal("non-scalar sub should be rejected")
	}
}
