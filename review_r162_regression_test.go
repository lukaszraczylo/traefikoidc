package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// flakyBackend is a backend whose Set can be made to fail. A successful
// Set writes to the map; once failSet is true, Set errors and leaves the
// previously-written (now stale) value in place. This reproduces the
// R162 write-propagation window.
type flakyBackend struct {
	m       map[string][]byte
	failSet bool
}

func (b *flakyBackend) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	if b.failSet {
		return fmt.Errorf("backend down")
	}
	b.m[k] = v
	return nil
}
func (b *flakyBackend) Get(_ context.Context, k string) ([]byte, time.Duration, bool, error) {
	v, ok := b.m[k]
	return v, 0, ok, nil
}
func (b *flakyBackend) Delete(_ context.Context, k string) (bool, error) {
	if _, ok := b.m[k]; ok {
		delete(b.m, k)
		return true, nil
	}
	return false, nil
}
func (b *flakyBackend) Exists(_ context.Context, k string) (bool, error) {
	_, ok := b.m[k]
	return ok, nil
}
func (b *flakyBackend) Clear(_ context.Context) error {
	b.m = map[string][]byte{}
	return nil
}
func (b *flakyBackend) GetStats() map[string]interface{} { return nil }
func (b *flakyBackend) Close() error                     { return nil }
func (b *flakyBackend) Ping(_ context.Context) error     { return nil }

// TestR162_CacheSetFailureServesFreshLocalNotStale guards the
// UniversalCache write-through path (universal_cache.go). Previously a
// failed backend Set left the OLD backend entry in place, and the next
// Get treated it as authoritative, overwriting the just-written fresh
// local value with stale data. The fix evicts the stale backend entry
// on propagation failure so Get falls through to the fresh local value.
// Fail-on-old: Get returns the stale backend value, not "fresh".
func TestR162_CacheSetFailureServesFreshLocalNotStale(t *testing.T) {
	fb := &flakyBackend{m: map[string][]byte{}}
	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:            NewLogger("error"),
		Type:              "token",
		DefaultTTL:        time.Minute,
		CleanupInterval:   time.Minute,
		EnableAutoCleanup: false,
	}, fb)

	// A real value reaches the backend (and local) while it works.
	uc.Set("k1", "old", time.Minute)
	fb.failSet = true                  // backend becomes unwritable
	uc.Set("k1", "fresh", time.Minute) // local has the fresh value; backend still has "old"

	got, ok := uc.Get("k1")
	if !ok {
		t.Fatal("k1 must still be served after a failed backend write")
	}
	if got != "fresh" {
		t.Fatalf("after a failed backend Set, Get returned stale value %q, want %q", got, "fresh")
	}
}

// TestR162_TestKeyIdHeaderHonorsRevokedJti guards the removal of the
// hardcoded test-header carve-out in verifyTokenWithOpts (token_manager.go).
// Any JWT whose header is exactly {alg:RS256,kid:test-key-id,typ:JWT} —
// a plausible production header — previously skipped BOTH jti blacklist
// Get checks, silently disabling external jti revocation / replay
// detection for that token. The fix drops the prefix special-case so the
// jti is honored like any other token.
// Fail-on-old: a test-key-id token whose jti was revoked still verifies OK.
func TestR162_TestKeyIdHeaderHonorsRevokedJti(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	oidc := &TraefikOidc{
		tokenCache:     NewTokenCache(),
		tokenBlacklist: &serializingCache{m: map[string]interface{}{}},
	}

	jti := generateRandomString(16)
	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "test-subject",
		"jti": jti,
	})
	if err != nil {
		t.Fatalf("createTestJWT: %v", err)
	}

	// Populate the positive token cache so verifyTokenWithOpts takes the
	// cache-short-circuit path (no signature verification needed).
	oidc.tokenCache.Set(token, map[string]interface{}{"jti": jti, "sub": "test-subject"}, 5*time.Minute)
	// External revocation of this jti.
	oidc.tokenBlacklist.Set(jti, true, 5*time.Minute)

	if err := oidc.verifyTokenWithOpts(token, verifyOpts{}); err == nil {
		t.Fatal("a token whose jti was revoked must be rejected even when its header is test-key-id")
	}
}

// TestR162_DCRPrivateKeyJwtBuildsSigner guards the R162 reconciliation in
// performDynamicClientRegistration (main.go). When DCR registers a client
// whose token-endpoint auth method is private_key_jwt but the static
// config did not set ClientAuthMethod=private_key_jwt, no
// ClientAssertionSigner was built at construction and every token
// exchange silently fell back to client_secret (empty for a secretless
// private_key_jwt client) and failed invalid_client. The fix builds the
// signer from the static key material after registration.
// Fail-on-old: after DCR, clientAssertion stays nil.
func TestR162_DCRPrivateKeyJwtBuildsSigner(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID:     "dcr-client-id",
			ClientSecret: "dcr-client-secret",
			RedirectURIs: []string{"https://example.com/callback"},
		})
	}))
	defer server.Close()

	logger := NewLogger("error")
	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs:            []string{"https://example.com/callback"},
			TokenEndpointAuthMethod: "private_key_jwt",
		},
	}
	registrar := NewDynamicClientRegistrar(server.Client(), logger, dcrConfig, server.URL)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tObj := &TraefikOidc{
		dynamicClientRegistrar: registrar,
		dcrConfig:              &DynamicClientRegistrationConfig{RegistrationEndpoint: server.URL},
		logger:                 logger,
		ctx:                    context.Background(),
		dcrClientAssertionBuilder: func() (*ClientAssertionSigner, error) {
			return NewClientAssertionSigner(pemBytes, "RS256", "test-key-id")
		},
	}

	tObj.performDynamicClientRegistration()

	if tObj.clientAuthMethod != "private_key_jwt" {
		t.Fatalf("clientAuthMethod=%q, want private_key_jwt", tObj.clientAuthMethod)
	}
	if tObj.clientAssertion == nil {
		t.Fatal("DCR registered a private_key_jwt client but no client-assertion signer was built")
	}
}
