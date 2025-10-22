//go:build !yaegi

package token

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// Mock implementations for validator tests
type mockTokenCache struct {
	data map[string]map[string]interface{}
	mu   sync.RWMutex
}

func newMockTokenCache() *mockTokenCache {
	return &mockTokenCache{
		data: make(map[string]map[string]interface{}),
	}
}

func (m *mockTokenCache) CacheToken(token string, claims map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[token] = claims
}

func (m *mockTokenCache) GetCachedToken(token string) (map[string]interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	claims, exists := m.data[token]
	return claims, exists
}

func (m *mockTokenCache) InvalidateToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, token)
}

func (m *mockTokenCache) StartCleanup(interval time.Duration) {
	// No-op for tests
}

func (m *mockTokenCache) StopCleanup() {
	// No-op for tests
}

// Validator tests
func TestNewValidator(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		Audience:       "test-audience",
		IssuerURL:      "https://issuer.example.com",
		JwksURL:        "https://issuer.example.com/jwks",
		TokenCache:     newMockTokenCache(),
		TokenBlacklist: newMockCache(),
		TokenTypeCache: newMockCache(),
		HTTPClient:     &http.Client{},
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	if validator == nil {
		t.Fatal("Expected NewValidator to return non-nil")
	}

	if validator.clientID != "test-client" {
		t.Error("Expected clientID to be set")
	}

	if validator.audience != "test-audience" {
		t.Error("Expected audience to be set")
	}

	if validator.issuerURL != "https://issuer.example.com" {
		t.Error("Expected issuerURL to be set")
	}
}

func TestNewValidator_NilMetadataMu(t *testing.T) {
	config := ValidatorConfig{
		ClientID: "test-client",
		// MetadataMu is nil
	}

	validator := NewValidator(config)

	if validator.metadataMu != nil {
		t.Error("Expected metadataMu to be nil when not provided")
	}
}

func TestValidator_VerifyToken_EmptyToken(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenCache:     newMockTokenCache(),
		TokenBlacklist: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	err := validator.VerifyToken("")
	if err == nil {
		t.Error("Expected error for empty token")
	}

	if err.Error() != "invalid JWT format: token is empty" {
		t.Errorf("Expected empty token error, got: %v", err)
	}
}

func TestValidator_VerifyToken_InvalidFormat(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenCache:     newMockTokenCache(),
		TokenBlacklist: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	// Token with only 2 parts (missing 3rd part)
	err := validator.VerifyToken("header.payload")
	if err == nil {
		t.Error("Expected error for invalid token format")
	}

	// Token with too many parts
	err = validator.VerifyToken("part1.part2.part3.part4")
	if err == nil {
		t.Error("Expected error for token with too many parts")
	}
}

func TestValidator_VerifyToken_TooShort(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenCache:     newMockTokenCache(),
		TokenBlacklist: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	err := validator.VerifyToken("ab.cd.ef")
	if err == nil {
		t.Error("Expected error for too short token")
	}

	if err.Error() != "token too short to be valid JWT" {
		t.Errorf("Expected too short error, got: %v", err)
	}
}

func TestValidator_DetermineTokenType(t *testing.T) {
	// Test ID token
	configID := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}
	validatorID := NewValidator(configID)

	jwtID := &JWT{
		Claims: map[string]interface{}{
			"nonce": "test-nonce",
		},
	}

	tokenType := validatorID.determineTokenType(jwtID)
	if tokenType != TokenTypeID {
		t.Errorf("Expected ID token type, got: %s", tokenType)
	}

	// Test access token with separate validator to avoid cache interference
	configAccess := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}
	validatorAccess := NewValidator(configAccess)

	jwtAccess := &JWT{
		Header: map[string]interface{}{
			"typ": "at+jwt",
		},
		Claims: map[string]interface{}{},
	}

	tokenType = validatorAccess.determineTokenType(jwtAccess)
	if tokenType != TokenTypeAccess {
		t.Errorf("Expected access token type, got: %s", tokenType)
	}
}

func TestValidator_DetectTokenType_Nonce(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			"nonce": "test-nonce-123",
		},
	}

	isIDToken := validator.detectTokenType(jwt, "test-token")
	if !isIDToken {
		t.Error("Expected nonce to indicate ID token")
	}
}

func TestValidator_DetectTokenType_AtJwt(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Header: map[string]interface{}{
			"typ": "at+jwt",
		},
		Claims: map[string]interface{}{},
	}

	isIDToken := validator.detectTokenType(jwt, "test-token")
	if isIDToken {
		t.Error("Expected at+jwt type to indicate access token")
	}
}

func TestValidator_DetectTokenType_TokenUse(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	// ID token
	jwtID := &JWT{
		Claims: map[string]interface{}{
			"token_use": "id",
		},
	}

	if !validator.detectTokenType(jwtID, "test-token-id") {
		t.Error("Expected token_use=id to indicate ID token")
	}

	// Access token
	jwtAccess := &JWT{
		Claims: map[string]interface{}{
			"token_use": "access",
		},
	}

	if validator.detectTokenType(jwtAccess, "test-token-access") {
		t.Error("Expected token_use=access to indicate access token")
	}
}

func TestValidator_DetectTokenType_Scope(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			"scope": "openid profile email",
		},
	}

	isIDToken := validator.detectTokenType(jwt, "test-token")
	if isIDToken {
		t.Error("Expected scope claim to indicate access token")
	}
}

func TestValidator_DetectTokenType_AudienceMatching(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client-id",
		TokenTypeCache: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	// Single audience matching client ID
	jwtSingleAud := &JWT{
		Claims: map[string]interface{}{
			"aud": "test-client-id",
		},
	}

	if !validator.detectTokenType(jwtSingleAud, "test-token-1") {
		t.Error("Expected matching audience to indicate ID token")
	}

	// Array audience with matching client ID
	jwtArrayAud := &JWT{
		Claims: map[string]interface{}{
			"aud": []interface{}{"test-client-id"},
		},
	}

	if !validator.detectTokenType(jwtArrayAud, "test-token-2") {
		t.Error("Expected matching audience array to indicate ID token")
	}

	// Non-matching audience
	jwtNoMatch := &JWT{
		Claims: map[string]interface{}{
			"aud": "different-audience",
		},
	}

	if validator.detectTokenType(jwtNoMatch, "test-token-3") {
		t.Error("Expected non-matching audience to indicate access token")
	}
}

func TestValidator_DetectTokenType_Caching(t *testing.T) {
	cache := newMockCache()
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: cache,
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
	jwt := &JWT{
		Claims: map[string]interface{}{
			"nonce": "test",
		},
	}

	// First call - should cache
	isIDToken := validator.detectTokenType(jwt, token)
	if !isIDToken {
		t.Error("Expected ID token")
	}

	// Verify cache was populated
	cacheKey := token[:32]
	cached, exists := cache.Get(cacheKey)
	if !exists {
		t.Error("Expected token type to be cached")
	}

	if isID, ok := cached["is_id_token"].(bool); !ok || !isID {
		t.Error("Expected cached value to be true for ID token")
	}

	// Modify JWT but use cached value
	jwt.Claims = map[string]interface{}{
		"scope": "openid", // Would indicate access token
	}

	// Should still return cached ID token result
	isIDToken = validator.detectTokenType(jwt, token)
	if !isIDToken {
		t.Error("Expected cached ID token result")
	}
}

func TestValidator_CheckJTIBlacklist_Disabled(t *testing.T) {
	config := ValidatorConfig{
		ClientID:               "test-client",
		DisableReplayDetection: true,
		TokenBlacklist:         newMockCache(),
		MetadataMu:             &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			"jti": "blacklisted-jti",
		},
	}

	// Should not check blacklist when disabled
	err := validator.checkJTIBlacklist(jwt, "test-token")
	if err != nil {
		t.Errorf("Expected no error when replay detection disabled, got: %v", err)
	}
}

func TestValidator_CheckJTIBlacklist_NoJTI(t *testing.T) {
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenBlacklist: newMockCache(),
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			// No JTI claim
		},
	}

	err := validator.checkJTIBlacklist(jwt, "test-token")
	if err != nil {
		t.Errorf("Expected no error when JTI missing, got: %v", err)
	}
}

func TestValidator_AddJTIToBlacklist(t *testing.T) {
	blacklist := newMockCache()
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenBlacklist: blacklist,
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			"jti": "test-jti-123",
		},
	}

	validator.addJTIToBlacklist(jwt)

	// Verify JTI was blacklisted
	data, exists := blacklist.Get("test-jti-123")
	if !exists {
		t.Error("Expected JTI to be blacklisted")
	}

	if reason, ok := data["reason"].(string); !ok || reason != "jti_replay_prevention" {
		t.Error("Expected JTI blacklist reason to be jti_replay_prevention")
	}
}

func TestValidator_AddJTIToBlacklist_Disabled(t *testing.T) {
	blacklist := newMockCache()
	config := ValidatorConfig{
		ClientID:               "test-client",
		DisableReplayDetection: true,
		TokenBlacklist:         blacklist,
		MetadataMu:             &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			"jti": "test-jti",
		},
	}

	validator.addJTIToBlacklist(jwt)

	// Should not blacklist when disabled
	_, exists := blacklist.Get("test-jti")
	if exists {
		t.Error("Expected JTI not to be blacklisted when replay detection disabled")
	}
}

func TestValidator_AddJTIToBlacklist_NoJTI(t *testing.T) {
	blacklist := newMockCache()
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenBlacklist: blacklist,
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwt := &JWT{
		Claims: map[string]interface{}{
			// No JTI
		},
	}

	validator.addJTIToBlacklist(jwt)

	// Should handle gracefully
	if len(blacklist.data) != 0 {
		t.Error("Expected no entries in blacklist when JTI missing")
	}
}

func TestValidator_CacheTokenType(t *testing.T) {
	cache := newMockCache()
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: cache,
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	validator.cacheTokenType("cache-key-123", true)

	data, exists := cache.Get("cache-key-123")
	if !exists {
		t.Error("Expected token type to be cached")
	}

	if isID, ok := data["is_id_token"].(bool); !ok || !isID {
		t.Error("Expected is_id_token to be true")
	}

	if _, ok := data["cached_at"].(int64); !ok {
		t.Error("Expected cached_at timestamp")
	}
}

func TestValidator_CacheVerifiedToken(t *testing.T) {
	tokenCache := newMockTokenCache()
	config := ValidatorConfig{
		ClientID:   "test-client",
		TokenCache: tokenCache,
		MetadataMu: &sync.RWMutex{},
	}

	validator := NewValidator(config)

	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	validator.cacheVerifiedToken("test-token", claims)

	cached, exists := tokenCache.GetCachedToken("test-token")
	if !exists {
		t.Error("Expected token to be cached")
	}

	if cached["sub"] != "user123" {
		t.Error("Expected cached claims to match")
	}
}

func TestValidator_CheckRateLimit(t *testing.T) {
	config := ValidatorConfig{
		ClientID:   "test-client",
		MetadataMu: &sync.RWMutex{},
	}

	validator := NewValidator(config)

	// Default implementation returns true
	if !validator.checkRateLimit() {
		t.Error("Expected checkRateLimit to return true by default")
	}
}

func TestValidator_FindMatchingKey(t *testing.T) {
	config := ValidatorConfig{
		ClientID:   "test-client",
		MetadataMu: &sync.RWMutex{},
	}

	validator := NewValidator(config)

	jwks := &JWKS{
		Keys: []JWK{
			{Kid: "key-1", Kty: "RSA"},
			{Kid: "key-2", Kty: "RSA"},
			{Kid: "key-3", Kty: "RSA"},
		},
	}

	key := validator.findMatchingKey(jwks, "key-2")
	if key == nil {
		t.Fatal("Expected to find matching key")
	}

	if key.Kid != "key-2" {
		t.Errorf("Expected kid 'key-2', got '%s'", key.Kid)
	}

	// Test non-existent key
	key = validator.findMatchingKey(jwks, "key-999")
	if key != nil {
		t.Error("Expected nil for non-existent key")
	}

	// Test nil JWKS
	key = validator.findMatchingKey(nil, "key-1")
	if key != nil {
		t.Error("Expected nil for nil JWKS")
	}
}

// Race condition tests
func TestValidator_ConcurrentTokenTypeDetection(t *testing.T) {
	cache := newMockCache()
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenTypeCache: cache,
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	var wg sync.WaitGroup
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-concurrent"

	jwt := &JWT{
		Claims: map[string]interface{}{
			"nonce": "test",
		},
	}

	// Concurrent token type detection
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = validator.detectTokenType(jwt, token)
		}()
	}

	wg.Wait()

	// Should have cached the result
	cacheKey := token[:32]
	if _, exists := cache.Get(cacheKey); !exists {
		t.Error("Expected token type to be cached after concurrent access")
	}
}

func TestValidator_ConcurrentJTIBlacklisting(t *testing.T) {
	blacklist := newMockCache()
	config := ValidatorConfig{
		ClientID:       "test-client",
		TokenBlacklist: blacklist,
		MetadataMu:     &sync.RWMutex{},
	}

	validator := NewValidator(config)

	var wg sync.WaitGroup

	// Concurrent JTI blacklisting
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			jwt := &JWT{
				Claims: map[string]interface{}{
					"jti": string(rune('A' + idx%26)),
				},
			}
			validator.addJTIToBlacklist(jwt)
		}(i)
	}

	wg.Wait()

	// Should have multiple JTIs blacklisted
	if len(blacklist.data) == 0 {
		t.Error("Expected JTIs to be blacklisted")
	}
}
