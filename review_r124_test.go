package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// NewMemoryBackendForTest returns a cache backend backed by an in-process
// miniredis instance, for white-box tests that need a real CacheBackend
// without depending on a live Redis server. internal/cache's in-memory
// backend was removed as unreachable dead code (FIX-43); RedisBackend
// against miniredis is the project's standard lightweight substitute (see
// e.g. universal_cache_serialization_test.go).
//
// The miniredis server is registered against t.Cleanup so it (and its
// listener goroutine) is closed when t ends. Callers still defer
// backend.Close() to close the RedisBackend connection pool; that alone
// does not stop the miniredis server.
func NewMemoryBackendForTest(t *testing.T) (backends.CacheBackend, error) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		return nil, err
	}
	t.Cleanup(mr.Close)
	return backends.NewRedisBackend(backends.DefaultRedisConfig(mr.Addr()))
}

func dcrTestRegistrar() *DynamicClientRegistrar {
	return NewDynamicClientRegistrar(&http.Client{}, GetSingletonNoOpLogger(), &DynamicClientRegistrationConfig{
		ClientMetadata: &ClientRegistrationMetadata{
			TokenEndpointAuthMethod: "client_secret_post",
			RedirectURIs:            []string{"https://app.example.com/callback"},
		},
	}, "https://provider.example.com")
}

// TestDynamicRegistrar_LoadPathRejectsEmptySecret guards the R124 fix to
// dynamic_client_registration.go areCredentialsValid: a stored record with
// a client_id but empty client_secret was accepted on the load path and
// installed as t.clientSecret="", breaking every token exchange. The load
// path must reject secret-less records for secret-based auth methods,
// mirroring the fresh-registration check.
func TestDynamicRegistrar_LoadPathRejectsEmptySecret(t *testing.T) {
	r := dcrTestRegistrar()

	if r.areCredentialsValid(&ClientRegistrationResponse{ClientID: "c", ClientSecret: ""}) {
		t.Fatal("a secret-based stored record with an empty client_secret must be rejected")
	}
	if !r.areCredentialsValid(&ClientRegistrationResponse{ClientID: "c", ClientSecret: "s"}) {
		t.Fatal("a secret-based stored record with a client_secret must be accepted")
	}
}

// TestDynamicRegistrar_BuildRegRequestSeedsRuntimeScopes guards the R124
// fix to dynamic_client_registration.go buildRegistrationRequest: with no
// operator registration scope, the request must advertise the runtime auth
// scopes so IdPs that only grant registered scopes (Keycloak
// offline_access, Auth0) accept the later token/refresh grant.
func TestDynamicRegistrar_BuildRegRequestSeedsRuntimeScopes(t *testing.T) {
	r := dcrTestRegistrar()
	r.scopes = []string{"openid", "profile", "offline_access"}

	body, err := r.buildRegistrationRequest()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if scope, ok := reqData["scope"].(string); !ok || scope != "openid profile offline_access" {
		t.Fatalf("registration must advertise runtime scopes when no operator scope set, got %q", reqData["scope"])
	}
}

// TestUpdateMetadataEndpoints_PreservesIssuerOnEmpty guards the R124 fix to
// main.go updateMetadataEndpoints: on a refresh whose discovery document
// has an empty (or host-mismatched, hence nulled) issuer, the previously-
// good issuer must be preserved rather than wiped to "", which would
// permanently brick auth until a later refresh restored it.
func TestUpdateMetadataEndpoints_PreservesIssuerOnEmpty(t *testing.T) {
	tObj := &TraefikOidc{
		logger:      GetSingletonNoOpLogger(),
		providerURL: "https://provider.example.com",
		issuerURL:   "https://issuer.example.com",
	}

	tObj.updateMetadataEndpoints(&ProviderMetadata{Issuer: ""})

	if tObj.issuerURL != "https://issuer.example.com" {
		t.Fatalf("issuer must be preserved when discovery is empty, got %q", tObj.issuerURL)
	}
	// The published snapshot must agree.
	snap := tObj.metadataSnapshot.Load()
	if snap != nil {
		if ss, ok := snap.(*MetadataSnapshot); ok && ss.IssuerURL != "https://issuer.example.com" {
			t.Fatalf("snapshot issuer must also be preserved, got %q", ss.IssuerURL)
		}
	}
}

// TestValidateTokenExpiryRS_AppliesClockSkewLeeway guards the R124 fix to
// token_validation_rs.go validateTokenExpiryRS: the final expiry gate
// checked exp with no clock-skew leeway, while jwt.Verify grants
// ClockSkewToleranceFuture. A token within the 2-minute post-exp window
// was granted by Verify then downgraded to expired here, forcing a
// needless refresh/re-auth. The gate must apply the same leeway.
func TestValidateTokenExpiryRS_AppliesClockSkewLeeway(t *testing.T) {
	tObj := &TraefikOidc{
		logger: GetSingletonNoOpLogger(),
	}
	tObj.tokenCache = NewTokenCache()
	// Token expired 60s ago, within the 2-minute ClockSkewToleranceFuture
	// leeway window: it must still be considered valid here.
	claims := map[string]interface{}{"exp": float64(time.Now().Add(-60 * time.Second).Unix())}
	tObj.tokenCache.Set("tok", claims, time.Hour)

	valid, _, _ := tObj.validateTokenExpiryRS(&requestState{}, "tok")
	if !valid {
		t.Fatal("token 60s past exp must still be valid within the clock-skew leeway window")
	}
}

// TestShouldBypassAuth_PassesOptions guards the R124 fix to middleware.go
// shouldBypassAuth: CORS preflights carry no session cookie and were
// 401'd (with no Access-Control-Allow-* headers), so the browser blocked
// cross-origin SPA->API calls. A genuine preflight (Origin +
// Access-Control-Request-Method, the shape every browser actually sends)
// must be passed through. FIX-02 narrowed the original R124 bypass, which
// matched on the OPTIONS method alone regardless of these headers; see
// TestShouldBypassAuth_BareOptionsDoesNotBypass in
// fix02_options_bypass_test.go for the negative case that guards against
// that regression.
func TestShouldBypassAuth_PassesOptions(t *testing.T) {
	tObj := &TraefikOidc{
		logger: GetSingletonNoOpLogger(),
	}
	req := httptest.NewRequest(http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	bypass, reason := tObj.shouldBypassAuth(req)
	if !bypass {
		t.Fatal("OPTIONS preflight must bypass auth")
	}
	if reason != bypassReasonOptions {
		t.Fatalf("OPTIONS bypass reason = %q, want %q", reason, bypassReasonOptions)
	}
}

// TestGetPublicKey_RefreshesPastCooldownOnKidMiss guards the R124 fix to
// jwk.go GetPublicKey: when a cached (cooldown-window) refresh serves a
// keyset lacking the requested kid because the provider is lagging its own
// rotation, GetPublicKey must do one ungated live refresh to pick up the
// newly-published key instead of 401ing for up to the whole cooldown
// window.
func TestGetPublicKey_RefreshesPastCooldownOnKidMiss(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const kid = "rotating-kid"
	kidJWK := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	otherJWK := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "some-other-key",
		N: base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&fetchCount, 1)
		if n == 1 {
			// First fetch: the provider is lagging its own rotation —
			// the keyset is non-empty but does not yet contain the kid.
			_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{otherJWK}})
			return
		}
		// Second (ungated) fetch: the rotation has now propagated.
		_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{kidJWK}})
	}))
	defer server.Close()

	backend, err := NewMemoryBackendForTest(t)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:   CacheTypeJWK,
		Logger: GetSingletonNoOpLogger(),
	}, backend)
	defer cache.Close()

	jwkCache := &JWKCache{cache: cache}
	ctx := context.Background()

	// Call 1: live (fresh) refresh returns a keyset lacking the kid.
	if _, err := jwkCache.GetPublicKey(ctx, server.URL, kid, http.DefaultClient); err == nil {
		t.Fatalf("call 1 must fail: provider had not yet published the kid")
	}
	// The cooldown is now recorded, so call 2's gated refresh serves the
	// cached kid-lacking set; the fix then does one ungated live refresh
	// which picks up the just-published key.
	pub, err := jwkCache.GetPublicKey(ctx, server.URL, kid, http.DefaultClient)
	if err != nil {
		t.Fatalf("call 2 must recover the key on the ungated refresh, got: %v", err)
	}
	if pub == nil {
		t.Fatal("GetPublicKey returned nil key")
	}
	if got := atomic.LoadInt32(&fetchCount); got != 2 {
		t.Fatalf("expected exactly 2 live fetches (1 fresh + 1 ungated pick-up), got %d", got)
	}
}
