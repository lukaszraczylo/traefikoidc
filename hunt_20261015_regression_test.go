package traefikoidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnhanceSessionSecurity_CaseVariantForwardedHostStaysHostScoped(t *testing.T) {
	cases := []struct {
		name string
		xfh  string
	}{
		{name: "exact-case parent", xfh: "corp.example.com"},
		{name: "upper-case parent", xfh: "CORP.example.com"},
		{name: "mixed-case parent", xfh: "Corp.Example.COM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := createTestSessionManager(t)
			t.Cleanup(func() { _ = sm.Shutdown() })
			req := httptest.NewRequest(http.MethodGet, "https://app.corp.example.com/", nil)
			req.Host = "app.corp.example.com"
			req.Header.Set("X-Forwarded-Host", tc.xfh)
			opts := sm.EnhanceSessionSecurity(nil, req)
			if opts.Domain != "app.corp.example.com" {
				t.Fatalf("Domain = %q, want host-scoped app.corp.example.com", opts.Domain)
			}
		})
	}

	t.Run("case-variant forwarded host equal to serving host is kept", func(t *testing.T) {
		sm := createTestSessionManager(t)
		t.Cleanup(func() { _ = sm.Shutdown() })
		req := httptest.NewRequest(http.MethodGet, "https://internal.svc/", nil)
		req.Host = "internal.svc"
		req.Header.Set("X-Forwarded-Host", "App.Example.com")
		opts := sm.EnhanceSessionSecurity(nil, req)
		if opts.Domain != "app.example.com" {
			t.Fatalf("Domain = %q, want app.example.com", opts.Domain)
		}
	})
}

func TestEnforceIatAge_RejectsFutureIat(t *testing.T) {
	const maxAge = 24 * time.Hour
	now := time.Now()
	cases := []struct {
		name    string
		iat     time.Time
		wantErr bool
	}{
		{name: "now", iat: now},
		{name: "within future skew", iat: now.Add(ClockSkewToleranceFuture / 2)},
		{name: "one hour ahead", iat: now.Add(time.Hour), wantErr: true},
		{name: "just beyond skew", iat: now.Add(ClockSkewToleranceFuture + 10*time.Second), wantErr: true},
		{name: "older than max age", iat: now.Add(-48 * time.Hour), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceIatAge(map[string]interface{}{"iat": float64(tc.iat.Unix())}, maxAge)
			if (err != nil) != tc.wantErr {
				t.Fatalf("enforceIatAge err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestJWKCache_CooldownServesParsedEntryWithoutReparse(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	c := NewJWKCache()
	url := fmt.Sprintf("https://jwks.invalid/%d", time.Now().UnixNano())
	// The raw set is empty, so only the pre-parsed entry can satisfy the lookup.
	_ = c.cache.SetLocal(url, &JWKSet{}, time.Hour)
	_ = c.cache.SetLocal(url+parsedKeysSuffix, &parsedJWKS{keys: map[string]crypto.PublicKey{"k1": &priv.PublicKey}}, time.Hour)
	c.lastSignatureRefresh[url] = time.Now()

	got, err := c.getPublicKeyFresh(context.Background(), url, "k1", http.DefaultClient)
	if err != nil {
		t.Fatalf("getPublicKeyFresh: %v", err)
	}
	if got != crypto.PublicKey(&priv.PublicKey) {
		t.Fatal("cooldown branch did not serve the cached parsed key")
	}
}

func TestFrontchannelLogout_FloodCannotEvictSignedMarkers(t *testing.T) {
	cache := &CacheInterfaceWrapper{cache: NewUniversalCache(UniversalCacheConfig{
		Type:             CacheTypeSession,
		MaxSize:          5000,
		DefaultTTL:       sessionInvalidationTTL,
		Logger:           NewLogger("error"),
		SkipAutoCleanup:  true,
		MonotonicMarkers: true,
	})}
	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		enableFrontchannelLogout: true,
		sessionInvalidationCache: cache,
		issuerURL:                "https://idp.example.com",
	}
	t.Cleanup(func() { _ = cache.cache.Close() })

	if err := oidc.invalidateSession("", "real-subject"); err != nil {
		t.Fatalf("invalidateSession: %v", err)
	}
	if err := oidc.checkAndMarkLogoutJTIProcessed("real-jti", time.Now().Unix()); err != nil {
		t.Fatalf("mark jti: %v", err)
	}

	for i := 0; i < 6000; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/fc?iss=https://idp.example.com&sid=flood-%d", i), nil)
		rw := httptest.NewRecorder()
		oidc.handleFrontchannelLogout(rw, req)
		if rw.Code != http.StatusOK {
			t.Fatalf("flood request %d: status %d", i, rw.Code)
		}
	}

	if _, ok := cache.Get(oidc.buildSessionInvalidationKey("sub", "real-subject")); !ok {
		t.Error("backchannel sub marker evicted by front-channel flood")
	}
	if err := oidc.checkAndMarkLogoutJTIProcessed("real-jti", time.Now().Unix()); err == nil {
		t.Error("jti replay marker evicted by front-channel flood: replay accepted")
	}
	held := 0
	for i := 0; i < 6000; i++ {
		if _, ok := cache.Get(oidc.buildSessionInvalidationKey("sid", fmt.Sprintf("flood-%d", i))); ok {
			held++
		}
	}
	if held > maxFrontchannelMarkers {
		t.Errorf("front-channel markers held = %d, want <= %d", held, maxFrontchannelMarkers)
	}
	if _, ok := cache.Get(oidc.buildSessionInvalidationKey("sid", "flood-5999")); !ok {
		t.Error("most recent front-channel marker must remain")
	}
}

func TestMarkerQuota_Admit(t *testing.T) {
	var q markerQuota
	if got := q.admit("a", 2); got != "" {
		t.Errorf("admit a = %q, want none", got)
	}
	if got := q.admit("a", 2); got != "" {
		t.Errorf("re-admit a = %q, want none", got)
	}
	if got := q.admit("b", 2); got != "" {
		t.Errorf("admit b = %q, want none", got)
	}
	if got := q.admit("c", 2); got != "a" {
		t.Errorf("admit c evicted %q, want a", got)
	}
}

func TestServeHTTP_InitWaitQueueFullFailsFast(t *testing.T) {
	oidc := &TraefikOidc{
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
	}
	oidc.initWaiters = maxInitWaiters

	rw := httptest.NewRecorder()
	start := time.Now()
	oidc.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/protected", nil))

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rw.Code)
	}
	if rw.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("rejected after %v, want immediate", time.Since(start))
	}
	if oidc.initWaiters != maxInitWaiters {
		t.Errorf("initWaiters = %d, want unchanged %d", oidc.initWaiters, maxInitWaiters)
	}
}

func TestServeHTTP_InitWaiterReleasedOnCancel(t *testing.T) {
	oidc := &TraefikOidc{
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil).WithContext(ctx)
	oidc.ServeHTTP(httptest.NewRecorder(), req)
	if oidc.initWaiters != 0 {
		t.Fatalf("initWaiters = %d after canceled wait, want 0", oidc.initWaiters)
	}
}

func TestCleanupOldCookies_CapsDeletionHeaders(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-bytes-long!!", false, "cookie.example.com", "testpref", 0, newNoOpLogger())
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Shutdown() })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "a.b.example.com"
	for i := 0; i < 180; i++ {
		req.AddCookie(&http.Cookie{Name: fmt.Sprintf("testpref_%d", i), Value: "x"})
	}
	rw := httptest.NewRecorder()
	sm.CleanupOldCookies(rw, req)

	got := len(rw.Result().Cookies())
	if got == 0 {
		t.Fatal("expected deletion cookies for the first wave")
	}
	if limit := maxCleanupCookies * 4; got > limit {
		t.Fatalf("deletion Set-Cookie headers = %d, want <= %d", got, limit)
	}
	for _, c := range rw.Result().Cookies() {
		if !strings.HasPrefix(c.Name, "testpref_") {
			t.Errorf("unexpected deletion cookie %q", c.Name)
		}
	}
}
