package cache

import (
	"encoding/json"
	"fmt"
	"time"
)

// TypedCache provides a type-safe wrapper around Cache for specific types
type TypedCache[T any] struct {
	cache  *Cache
	prefix string
}

// NewTypedCache creates a new typed cache wrapper
func NewTypedCache[T any](cache *Cache, prefix string) *TypedCache[T] {
	return &TypedCache[T]{
		cache:  cache,
		prefix: prefix,
	}
}

// Set stores a typed value
func (tc *TypedCache[T]) Set(key string, value T, ttl time.Duration) error {
	prefixedKey := tc.prefix + key
	return tc.cache.Set(prefixedKey, value, ttl)
}

// Get retrieves a typed value
func (tc *TypedCache[T]) Get(key string) (T, bool) {
	var zero T
	prefixedKey := tc.prefix + key

	value, exists := tc.cache.Get(prefixedKey)
	if !exists {
		return zero, false
	}

	// Try direct type assertion first
	if typedValue, ok := value.(T); ok {
		return typedValue, true
	}

	// If that fails, try JSON marshaling/unmarshaling for complex types
	data, err := json.Marshal(value)
	if err != nil {
		return zero, false
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return zero, false
	}

	return result, true
}

// Delete removes a typed value
func (tc *TypedCache[T]) Delete(key string) {
	prefixedKey := tc.prefix + key
	tc.cache.Delete(prefixedKey)
}

// Clear removes all items with the prefix
func (tc *TypedCache[T]) Clear() {
	// Note: This clears the entire underlying cache
	// In a production system, you might want to implement prefix-based clearing
	tc.cache.Clear()
}

// Size returns the size of the underlying cache
func (tc *TypedCache[T]) Size() int {
	return tc.cache.Size()
}

// TokenCache provides specialized caching for JWT tokens
type TokenCache struct {
	cache *TypedCache[map[string]interface{}]
}

// NewTokenCache creates a new token cache
func NewTokenCache(baseCache *Cache) *TokenCache {
	return &TokenCache{
		cache: NewTypedCache[map[string]interface{}](baseCache, "token:"),
	}
}

// Set stores parsed token claims
func (tc *TokenCache) Set(token string, claims map[string]interface{}, expiration time.Duration) error {
	return tc.cache.Set(token, claims, expiration)
}

// Get retrieves cached claims for a token
func (tc *TokenCache) Get(token string) (map[string]interface{}, bool) {
	return tc.cache.Get(token)
}

// Delete removes a token from cache
func (tc *TokenCache) Delete(token string) {
	tc.cache.Delete(token)
}

// SetBlacklisted marks a token as blacklisted
func (tc *TokenCache) SetBlacklisted(token string, ttl time.Duration) error {
	blacklistKey := "blacklist:" + token
	// Store blacklisted status as a map to match the type
	blacklistData := map[string]interface{}{"blacklisted": true}
	return tc.cache.Set(blacklistKey, blacklistData, ttl)
}

// IsBlacklisted checks if a token is blacklisted
func (tc *TokenCache) IsBlacklisted(token string) bool {
	blacklistKey := "blacklist:" + token
	value, exists := tc.cache.Get(blacklistKey)
	if !exists {
		return false
	}
	// Check if the blacklist data indicates blacklisted status
	if data, ok := value["blacklisted"]; ok {
		blacklisted, _ := data.(bool)
		return blacklisted
	}
	return false
}

// MetadataCache provides specialized caching for provider metadata
type MetadataCache struct {
	cache  *Cache
	config MetadataConfig
}

// ProviderMetadata represents OIDC provider metadata
type ProviderMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// NewMetadataCache creates a new metadata cache
func NewMetadataCache(baseCache *Cache, config MetadataConfig) *MetadataCache {
	return &MetadataCache{
		cache:  baseCache,
		config: config,
	}
}

// Set stores provider metadata with grace period support
func (mc *MetadataCache) Set(providerURL string, metadata *ProviderMetadata, ttl time.Duration) error {
	if metadata == nil {
		return fmt.Errorf("metadata cannot be nil")
	}

	key := "metadata:" + providerURL

	// Apply grace period if configured
	if mc.config.GracePeriod > 0 {
		ttl += mc.config.GracePeriod
	}

	// Store as JSON for consistency
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return mc.cache.Set(key, data, ttl)
}

// Get retrieves provider metadata from cache
func (mc *MetadataCache) Get(providerURL string) (*ProviderMetadata, bool) {
	key := "metadata:" + providerURL
	value, exists := mc.cache.Get(key)
	if !exists {
		return nil, false
	}

	// Handle different value types
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return nil, false
	}

	var metadata ProviderMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, false
	}

	return &metadata, true
}

// Delete removes provider metadata
func (mc *MetadataCache) Delete(providerURL string) {
	key := "metadata:" + providerURL
	mc.cache.Delete(key)
}

// JWKCache provides specialized caching for JWK sets
type JWKCache struct {
	cache *Cache
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c,omitempty"`
}

// NewJWKCache creates a new JWK cache
func NewJWKCache(baseCache *Cache) *JWKCache {
	return &JWKCache{
		cache: baseCache,
	}
}

// Set stores a JWK set
func (jc *JWKCache) Set(jwksURL string, jwks *JWKSet, ttl time.Duration) error {
	if jwks == nil {
		return fmt.Errorf("JWK set cannot be nil")
	}

	key := "jwk:" + jwksURL
	return jc.cache.Set(key, jwks, ttl)
}

// Get retrieves a JWK set from cache
func (jc *JWKCache) Get(jwksURL string) (*JWKSet, bool) {
	key := "jwk:" + jwksURL
	value, exists := jc.cache.Get(key)
	if !exists {
		return nil, false
	}

	jwks, ok := value.(*JWKSet)
	if !ok {
		// Try JSON conversion
		data, err := json.Marshal(value)
		if err != nil {
			return nil, false
		}

		var result JWKSet
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, false
		}
		return &result, true
	}

	return jwks, true
}

// Delete removes a JWK set from cache
func (jc *JWKCache) Delete(jwksURL string) {
	key := "jwk:" + jwksURL
	jc.cache.Delete(key)
}

// SessionCache provides specialized caching for sessions
type SessionCache struct {
	cache *TypedCache[SessionData]
}

// SessionData represents session information
type SessionData struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	ExpiresAt    time.Time              `json:"expires_at"`
	Claims       map[string]interface{} `json:"claims"`
}

// NewSessionCache creates a new session cache
func NewSessionCache(baseCache *Cache) *SessionCache {
	return &SessionCache{
		cache: NewTypedCache[SessionData](baseCache, "session:"),
	}
}

// Set stores session data
func (sc *SessionCache) Set(sessionID string, data SessionData, ttl time.Duration) error {
	return sc.cache.Set(sessionID, data, ttl)
}

// Get retrieves session data
func (sc *SessionCache) Get(sessionID string) (SessionData, bool) {
	return sc.cache.Get(sessionID)
}

// Delete removes a session
func (sc *SessionCache) Delete(sessionID string) {
	sc.cache.Delete(sessionID)
}

// Exists checks if a session exists
func (sc *SessionCache) Exists(sessionID string) bool {
	_, exists := sc.cache.Get(sessionID)
	return exists
}
