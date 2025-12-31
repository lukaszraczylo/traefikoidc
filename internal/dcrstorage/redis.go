package dcrstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Cache defines the interface for cache operations needed by RedisStore.
// This allows the main package to provide a cache implementation without
// creating circular dependencies.
type Cache interface {
	// Get retrieves a value from the cache
	Get(key string) (any, bool)
	// Set stores a value in the cache with a TTL
	Set(key string, value any, ttl time.Duration) error
	// Delete removes a value from the cache
	Delete(key string)
}

// RedisStore implements Store using a Cache-backed storage.
// This storage backend enables sharing DCR credentials across multiple Traefik instances
// in distributed environments (e.g., Kubernetes with multiple ingress pods).
type RedisStore struct {
	cache     Cache
	keyPrefix string
	logger    Logger
	mu        sync.RWMutex
}

// NewRedisStore creates a new cache-backed credentials store.
// The cache should be configured with a Redis backend for distributed storage.
// If keyPrefix is empty, defaults to "dcr:creds:"
func NewRedisStore(cache Cache, keyPrefix string, logger Logger) *RedisStore {
	if keyPrefix == "" {
		keyPrefix = "dcr:creds:"
	}
	if logger == nil {
		logger = NoOpLogger()
	}
	return &RedisStore{
		cache:     cache,
		keyPrefix: keyPrefix,
		logger:    logger,
	}
}

// makeKey creates a unique cache key for a provider URL.
// Uses SHA256 hash of the provider URL for consistent key generation across nodes.
func (s *RedisStore) makeKey(providerURL string) string {
	if providerURL == "" {
		return s.keyPrefix + "default"
	}
	hash := sha256.Sum256([]byte(providerURL))
	return s.keyPrefix + hex.EncodeToString(hash[:])
}

// Save stores the client registration response in the cache.
// TTL is calculated based on client_secret_expires_at if available.
func (s *RedisStore) Save(ctx context.Context, providerURL string, creds *ClientRegistrationResponse) error {
	if creds == nil {
		return fmt.Errorf("credentials cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.makeKey(providerURL)

	// Calculate TTL based on client_secret_expires_at if available
	ttl := 30 * 24 * time.Hour // Default: 30 days
	if creds.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(creds.ClientSecretExpiresAt, 0)
		ttl = time.Until(expiresAt)
		if ttl < 0 {
			return fmt.Errorf("credentials already expired")
		}
		// Add a small buffer to ensure we don't serve expired credentials
		if ttl > time.Minute {
			ttl -= time.Minute
		}
	}

	// Serialize credentials to JSON for storage
	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Store as string in cache (will be serialized by the cache backend)
	if err := s.cache.Set(key, string(data), ttl); err != nil {
		return fmt.Errorf("failed to store credentials in cache: %w", err)
	}

	s.logger.Debugf("Saved client credentials to cache with key %s (TTL: %v)", key, ttl)
	return nil
}

// Load retrieves stored credentials from the cache.
// Returns nil, nil if no credentials exist (not an error).
func (s *RedisStore) Load(ctx context.Context, providerURL string) (*ClientRegistrationResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := s.makeKey(providerURL)

	value, exists := s.cache.Get(key)
	if !exists {
		return nil, nil // No credentials stored - not an error
	}

	// Handle different value types from cache
	var jsonData string
	switch v := value.(type) {
	case string:
		jsonData = v
	case []byte:
		jsonData = string(v)
	default:
		// Try to see if it's already the struct (from local cache)
		if creds, ok := value.(*ClientRegistrationResponse); ok {
			return creds, nil
		}
		return nil, fmt.Errorf("unexpected credentials type in cache: %T", value)
	}

	var creds ClientRegistrationResponse
	if err := json.Unmarshal([]byte(jsonData), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials from cache: %w", err)
	}

	s.logger.Debugf("Loaded client credentials from cache with key %s", key)
	return &creds, nil
}

// Delete removes stored credentials from the cache
func (s *RedisStore) Delete(ctx context.Context, providerURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.makeKey(providerURL)
	s.cache.Delete(key)

	s.logger.Debugf("Deleted client credentials from cache with key %s", key)
	return nil
}

// Exists checks if credentials exist in the cache for a provider
func (s *RedisStore) Exists(ctx context.Context, providerURL string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := s.makeKey(providerURL)
	_, exists := s.cache.Get(key)

	return exists, nil
}
