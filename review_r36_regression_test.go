package traefikoidc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

// TestConfigValidate_DCRSkipsCredentialCheck covers the P1 fix: with Dynamic
// Client Registration (RFC 7591) enabled and no pre-provisioned client ID,
// Config.Validate must NOT reject the config for missing clientID/clientSecret
// (the provider provisions them at registration). Any other credential
// combination is still validated as before.
func TestConfigValidate_DCRSkipsCredentialCheck(t *testing.T) {
	base := Config{
		ProviderURL:         "https://issuer.example.com",
		CallbackURL:         "/callback",
		SessionEncryptionKey: "0123456789abcdef0123456789abcdef", // >= MinSessionEncryptionKeyLength
		RateLimit:           100,                               // >= MinRateLimit (10)
	}

	// Control: without DCR, an empty clientID must still be rejected.
	cfg := base
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected 'clientID is required' error when DCR is disabled and clientID is empty")
	}

	// P1 fix: with DCR enabled and empty clientID, validation must pass.
	cfg = base
	cfg.DynamicClientRegistration = &DynamicClientRegistrationConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected validation to pass with DCR enabled and empty clientID, got: %v", err)
	}

	// With DCR enabled but an explicit clientID, credential checks still apply:
	// a missing clientSecret with the default method must still be rejected.
	cfg = base
	cfg.DynamicClientRegistration = &DynamicClientRegistrationConfig{Enabled: true}
	cfg.ClientID = "explicit-client"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected 'clientSecret is required' error when clientID is supplied under DCR")
	}
}

// TestDCRBuildRegistrationRequestDefaultAuthMethod covers the P2 fix: the
// token_endpoint_auth_method registered with the provider must match the
// plugin's runtime client-auth default (client_secret_post, settings.go
// Config.Validate) so an IdP that enforces the registered method does not
// reject the plugin's token exchange.
func TestDCRBuildRegistrationRequestDefaultAuthMethod(t *testing.T) {
	cfg := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"/callback"},
		},
	}
	r := NewDynamicClientRegistrar(nil, nil, cfg, "https://issuer.example.com")
	body, err := r.buildRegistrationRequest()
	if err != nil {
		t.Fatalf("buildRegistrationRequest failed: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("failed to parse registration body: %v", err)
	}
	got, _ := data["token_endpoint_auth_method"].(string)
	if got != "client_secret_post" {
		t.Errorf("expected default token_endpoint_auth_method to be client_secret_post, got %q", got)
	}
}

// TestVerifyTokenNoSelfReplayMarkAfterCacheEviction covers the P2 fix: on the
// cookie path the same still-valid token is re-presented on every request, so
// verifyTokenWithOpts must not self-record its own JTI into the per-instance
// tokenBlacklist. Doing so turns an LRU eviction of the raw-token cache
// (MaxSize 1000 / 5 MiB) into a false "token replay detected" for a valid,
// unexpired session. Cross-path replay detection (shardedReplayCache) and
// re-presentation after a cache eviction must both keep working.
func TestVerifyTokenNoSelfReplayMarkAfterCacheEviction(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()
	cleanupReplayCache()
	initReplayCache()

	jti := generateRandomString(16)
	now := time.Now()
	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   jti,
	})
	if err != nil {
		t.Fatalf("failed to create test JWT: %v", err)
	}

	// First verification succeeds and records the JTI in the shared
	// replay cache for cross-path replay detection.
	if err := ts.tOidc.VerifyToken(token); err != nil {
		t.Fatalf("first verification should succeed: %v", err)
	}
	if !shardedReplayCache.Exists(jti) {
		t.Error("JTI should be recorded in the shared shardedReplayCache for cross-path replay detection")
	}
	// The per-instance tokenBlacklist must NOT be self-marked (this was the
	// false-positive source after raw-token-cache eviction).
	if blacklisted, exists := ts.tOidc.tokenBlacklist.Get(jti); exists && blacklisted != nil {
		t.Error("per-instance tokenBlacklist must not self-record the JTI (would cause false replay after cache eviction)")
	}

	// Simulate an LRU eviction of the raw-token cache entry, then re-present
	// the same still-valid token: it must be accepted, not flagged as replay.
	ts.tOidc.tokenCache.Delete(token)
	if err := ts.tOidc.VerifyToken(token); err != nil {
		t.Errorf("re-presentation after raw-token-cache eviction should succeed, got: %v", err)
	}
}

// TestMetadataRefreshSharedTaskNotStoppedOnFirstClose covers the GlueLifecycle
// P2 fix: the per-provider singleton metadata-refresh task (name derived from
// providerURL only) is shared by every live instance pointing at that
// provider. Close must gate stopping it on the LAST live instance (matching
// singleton-token-cleanup), otherwise one instance's teardown (e.g. a config
// reload) would kill 2h metadata refresh for a surviving sibling that never
// re-registers.
func TestMetadataRefreshSharedTaskNotStoppedOnFirstClose(t *testing.T) {
	// The live-instance counter is a shared package global. Pin it so this
	// test's relative count is deterministic regardless of shuffle order, and
	// restore it afterwards.
	prev := atomic.LoadInt32(&liveInstanceCount)
	defer atomic.StoreInt32(&liveInstanceCount, prev)
	atomic.StoreInt32(&liveInstanceCount, 0)

	rm := GetResourceManager()
	providerURL := "https://issuer.example.com"
	hash := sha256.Sum256([]byte(providerURL))
	taskName := "singleton-metadata-refresh-" + hex.EncodeToString(hash[:])[0:6]

	// Clear any leftover task from prior tests and register a fresh one.
	_ = rm.StopBackgroundTask(taskName)
	if err := rm.RegisterBackgroundTask(taskName, time.Hour, func() {}); err != nil {
		t.Fatalf("failed to register metadata task: %v", err)
	}
	if err := rm.StartBackgroundTask(taskName); err != nil {
		t.Fatalf("failed to start metadata task: %v", err)
	}

	// Two live instances share this provider (same task name).
	registerLiveInstance()
	registerLiveInstance()

	first := &TraefikOidc{name: "meter-first", providerURL: providerURL}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if !rm.IsTaskRunning(taskName) {
		t.Fatal("metadata-refresh task must survive the first (non-last) instance Close")
	}

	second := &TraefikOidc{name: "meter-second", providerURL: providerURL}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if rm.IsTaskRunning(taskName) {
		t.Error("metadata-refresh task should be stopped once the last instance closes")
	}
}
