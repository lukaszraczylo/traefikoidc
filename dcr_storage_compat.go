// Package traefikoidc provides OIDC authentication middleware for Traefik
package traefikoidc

import (
	"context"
	"fmt"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/dcrstorage"
)

// DCRStorageBackend represents the type of storage backend for DCR credentials.
// Alias for internal package type for backward compatibility.
type DCRStorageBackend = dcrstorage.StorageBackend

const (
	// DCRStorageBackendFile uses file-based storage (default for backward compatibility)
	DCRStorageBackendFile DCRStorageBackend = dcrstorage.StorageBackendFile

	// DCRStorageBackendRedis uses Redis for distributed storage
	DCRStorageBackendRedis DCRStorageBackend = dcrstorage.StorageBackendRedis

	// DCRStorageBackendAuto automatically selects Redis if available, otherwise file
	DCRStorageBackendAuto DCRStorageBackend = dcrstorage.StorageBackendAuto
)

// DCRCredentialsStore defines the interface for storing DCR credentials.
// This abstraction allows different storage backends (file, Redis) to be used
// for persisting OIDC Dynamic Client Registration credentials across nodes.
type DCRCredentialsStore interface {
	// Save stores the client registration response for a provider
	// The providerURL is used as a key to support multi-tenant scenarios
	Save(ctx context.Context, providerURL string, creds *ClientRegistrationResponse) error

	// Load retrieves stored credentials for a provider
	// Returns nil, nil if no credentials exist (not an error)
	Load(ctx context.Context, providerURL string) (*ClientRegistrationResponse, error)

	// Delete removes stored credentials for a provider
	Delete(ctx context.Context, providerURL string) error

	// Exists checks if credentials exist for a provider
	Exists(ctx context.Context, providerURL string) (bool, error)
}

// loggerAdapter adapts our Logger to the dcrstorage.Logger interface
type loggerAdapter struct {
	logger *Logger
}

func (l *loggerAdapter) Debug(msg string)                  { l.logger.Debug("%s", msg) }
func (l *loggerAdapter) Debugf(format string, args ...any) { l.logger.Debugf(format, args...) }
func (l *loggerAdapter) Info(msg string)                   { l.logger.Info("%s", msg) }
func (l *loggerAdapter) Infof(format string, args ...any)  { l.logger.Infof(format, args...) }
func (l *loggerAdapter) Error(msg string)                  { l.logger.Error("%s", msg) }
func (l *loggerAdapter) Errorf(format string, args ...any) { l.logger.Errorf(format, args...) }

// cacheAdapter adapts UniversalCache to dcrstorage.Cache interface
type cacheAdapter struct {
	cache *UniversalCache
}

func (c *cacheAdapter) Get(key string) (any, bool) {
	return c.cache.Get(key)
}

func (c *cacheAdapter) Set(key string, value any, ttl time.Duration) error {
	return c.cache.Set(key, value, ttl)
}

func (c *cacheAdapter) Delete(key string) {
	c.cache.Delete(key)
}

// fileStoreWrapper wraps dcrstorage.FileStore to implement DCRCredentialsStore
type fileStoreWrapper struct {
	inner *dcrstorage.FileStore
}

func (w *fileStoreWrapper) Save(ctx context.Context, providerURL string, creds *ClientRegistrationResponse) error {
	innerCreds := convertCredsToInternal(creds)
	return w.inner.Save(ctx, providerURL, innerCreds)
}

func (w *fileStoreWrapper) Load(ctx context.Context, providerURL string) (*ClientRegistrationResponse, error) {
	innerCreds, err := w.inner.Load(ctx, providerURL)
	if err != nil || innerCreds == nil {
		return nil, err
	}
	return convertCredsFromInternal(innerCreds), nil
}

func (w *fileStoreWrapper) Delete(ctx context.Context, providerURL string) error {
	return w.inner.Delete(ctx, providerURL)
}

func (w *fileStoreWrapper) Exists(ctx context.Context, providerURL string) (bool, error) {
	return w.inner.Exists(ctx, providerURL)
}

// basePath returns the base path used for storing credentials (for backward compatibility in tests)
func (w *fileStoreWrapper) basePath() string {
	return w.inner.BasePath()
}

// getFilePath returns the file path for storing credentials for a specific provider (for backward compatibility in tests)
func (w *fileStoreWrapper) getFilePath(providerURL string) string {
	return w.inner.GetFilePath(providerURL)
}

// redisStoreWrapper wraps dcrstorage.RedisStore to implement DCRCredentialsStore
type redisStoreWrapper struct {
	inner *dcrstorage.RedisStore
}

func (w *redisStoreWrapper) Save(ctx context.Context, providerURL string, creds *ClientRegistrationResponse) error {
	innerCreds := convertCredsToInternal(creds)
	return w.inner.Save(ctx, providerURL, innerCreds)
}

func (w *redisStoreWrapper) Load(ctx context.Context, providerURL string) (*ClientRegistrationResponse, error) {
	innerCreds, err := w.inner.Load(ctx, providerURL)
	if err != nil || innerCreds == nil {
		return nil, err
	}
	return convertCredsFromInternal(innerCreds), nil
}

func (w *redisStoreWrapper) Delete(ctx context.Context, providerURL string) error {
	return w.inner.Delete(ctx, providerURL)
}

func (w *redisStoreWrapper) Exists(ctx context.Context, providerURL string) (bool, error) {
	return w.inner.Exists(ctx, providerURL)
}

// FileCredentialsStore implements DCRCredentialsStore using file-based storage.
// This is the default storage backend for backward compatibility with existing deployments.
type FileCredentialsStore = fileStoreWrapper

// RedisCredentialsStore implements DCRCredentialsStore using Redis-backed cache.
// This storage backend enables sharing DCR credentials across multiple Traefik instances.
type RedisCredentialsStore = redisStoreWrapper

// NewFileCredentialsStore creates a new file-based credentials store.
// If basePath is empty, defaults to /tmp/oidc-client-credentials.json
func NewFileCredentialsStore(basePath string, logger *Logger) *FileCredentialsStore {
	var dcrLogger dcrstorage.Logger
	if logger != nil {
		dcrLogger = &loggerAdapter{logger: logger}
	}
	inner := dcrstorage.NewFileStore(basePath, dcrLogger)
	return &fileStoreWrapper{inner: inner}
}

// NewRedisCredentialsStore creates a new Redis-backed credentials store.
// The cache should be configured with a Redis backend for distributed storage.
// If keyPrefix is empty, defaults to "dcr:creds:"
func NewRedisCredentialsStore(cache *UniversalCache, keyPrefix string, logger *Logger) *RedisCredentialsStore {
	var dcrLogger dcrstorage.Logger
	if logger != nil {
		dcrLogger = &loggerAdapter{logger: logger}
	}
	cacheAdapt := &cacheAdapter{cache: cache}
	inner := dcrstorage.NewRedisStore(cacheAdapt, keyPrefix, dcrLogger)
	return &redisStoreWrapper{inner: inner}
}

// Helper functions to convert between main package and internal package types
func convertCredsToInternal(creds *ClientRegistrationResponse) *dcrstorage.ClientRegistrationResponse {
	if creds == nil {
		return nil
	}
	return &dcrstorage.ClientRegistrationResponse{
		SubjectType:             creds.SubjectType,
		LogoURI:                 creds.LogoURI,
		RegistrationAccessToken: creds.RegistrationAccessToken,
		RegistrationClientURI:   creds.RegistrationClientURI,
		Scope:                   creds.Scope,
		TokenEndpointAuthMethod: creds.TokenEndpointAuthMethod,
		TOSURI:                  creds.TOSURI,
		PolicyURI:               creds.PolicyURI,
		ClientSecret:            creds.ClientSecret,
		ApplicationType:         creds.ApplicationType,
		ClientID:                creds.ClientID,
		ClientName:              creds.ClientName,
		JWKSURI:                 creds.JWKSURI,
		ClientURI:               creds.ClientURI,
		Contacts:                creds.Contacts,
		GrantTypes:              creds.GrantTypes,
		ResponseTypes:           creds.ResponseTypes,
		RedirectURIs:            creds.RedirectURIs,
		ClientSecretExpiresAt:   creds.ClientSecretExpiresAt,
		ClientIDIssuedAt:        creds.ClientIDIssuedAt,
	}
}

func convertCredsFromInternal(creds *dcrstorage.ClientRegistrationResponse) *ClientRegistrationResponse {
	if creds == nil {
		return nil
	}
	return &ClientRegistrationResponse{
		SubjectType:             creds.SubjectType,
		LogoURI:                 creds.LogoURI,
		RegistrationAccessToken: creds.RegistrationAccessToken,
		RegistrationClientURI:   creds.RegistrationClientURI,
		Scope:                   creds.Scope,
		TokenEndpointAuthMethod: creds.TokenEndpointAuthMethod,
		TOSURI:                  creds.TOSURI,
		PolicyURI:               creds.PolicyURI,
		ClientSecret:            creds.ClientSecret,
		ApplicationType:         creds.ApplicationType,
		ClientID:                creds.ClientID,
		ClientName:              creds.ClientName,
		JWKSURI:                 creds.JWKSURI,
		ClientURI:               creds.ClientURI,
		Contacts:                creds.Contacts,
		GrantTypes:              creds.GrantTypes,
		ResponseTypes:           creds.ResponseTypes,
		RedirectURIs:            creds.RedirectURIs,
		ClientSecretExpiresAt:   creds.ClientSecretExpiresAt,
		ClientIDIssuedAt:        creds.ClientIDIssuedAt,
	}
}

// NewDCRCredentialsStore creates a DCRCredentialsStore based on configuration.
// This factory function handles backend selection logic:
//   - "file": Use file-based storage (default for backward compatibility)
//   - "redis": Use Redis exclusively (fails if Redis unavailable)
//   - "auto": Use Redis if available, fallback to file
func NewDCRCredentialsStore(
	config *DynamicClientRegistrationConfig,
	cacheManager *CacheManager,
	logger *Logger,
) (DCRCredentialsStore, error) {
	if config == nil {
		return nil, fmt.Errorf("DCR config is nil")
	}

	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	backend := config.StorageBackend
	if backend == "" {
		backend = string(DCRStorageBackendAuto) // Default to auto selection
	}

	switch DCRStorageBackend(backend) {
	case DCRStorageBackendFile:
		logger.Info("Using file-based storage for DCR credentials")
		return NewFileCredentialsStore(config.CredentialsFile, logger), nil

	case DCRStorageBackendRedis:
		cache := getDCRCache(cacheManager)
		if cache == nil {
			return nil, fmt.Errorf("redis storage requested but Redis/cache not configured")
		}
		logger.Info("Using Redis storage for DCR credentials")
		return NewRedisCredentialsStore(cache, config.RedisKeyPrefix, logger), nil

	case DCRStorageBackendAuto:
		// Try Redis first, fallback to file
		cache := getDCRCache(cacheManager)
		if cache != nil && cache.backend != nil {
			logger.Info("Auto-selected Redis storage for DCR credentials")
			return NewRedisCredentialsStore(cache, config.RedisKeyPrefix, logger), nil
		}
		logger.Info("Redis not available, using file storage for DCR credentials")
		return NewFileCredentialsStore(config.CredentialsFile, logger), nil

	default:
		return nil, fmt.Errorf("unknown DCR storage backend: %s", backend)
	}
}

// getDCRCache safely retrieves the DCR credentials cache from the cache manager
func getDCRCache(cacheManager *CacheManager) *UniversalCache {
	if cacheManager == nil {
		return nil
	}
	cacheManager.mu.RLock()
	defer cacheManager.mu.RUnlock()

	if cacheManager.manager == nil {
		return nil
	}

	return cacheManager.manager.GetDCRCredentialsCache()
}
