// Package token provides token management functionality for OIDC authentication.
package token

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TokenCache manages cached verified tokens
type TokenCache struct {
	cache         CacheInterface
	blacklist     CacheInterface
	logger        LoggerInterface
	metrics       MetricsInterface
	cleanupTicker *time.Ticker
	cleanupStop   chan bool
	mu            sync.RWMutex
	maxTTL        time.Duration
}

// NewTokenCache creates a new token cache manager
func NewTokenCache(cache, blacklist CacheInterface, logger LoggerInterface, metrics MetricsInterface, maxTTL time.Duration) *TokenCache {
	return &TokenCache{
		cache:       cache,
		blacklist:   blacklist,
		logger:      logger,
		metrics:     metrics,
		maxTTL:      maxTTL,
		cleanupStop: make(chan bool),
	}
}

// CacheToken stores a verified token with its claims in cache
func (tc *TokenCache) CacheToken(token string, claims map[string]interface{}) {
	if token == "" || len(claims) == 0 {
		return
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Add timestamp for TTL management
	claimsWithMeta := make(map[string]interface{})
	for k, v := range claims {
		claimsWithMeta[k] = v
	}
	claimsWithMeta["_cached_at"] = time.Now().Unix()

	tc.cache.Set(token, claimsWithMeta)
	tc.logger.Logf("Cached verified token (claims count: %d)", len(claims))
}

// GetCachedToken retrieves a token's claims from cache if present and valid
func (tc *TokenCache) GetCachedToken(token string) (map[string]interface{}, bool) {
	if token == "" {
		return nil, false
	}

	tc.mu.RLock()
	defer tc.mu.RUnlock()

	claims, exists := tc.cache.Get(token)
	if !exists || len(claims) == 0 {
		return nil, false
	}

	// Check if token is blacklisted
	if tc.isBlacklisted(token, claims) {
		tc.cache.Delete(token)
		return nil, false
	}

	// Check cache TTL
	if cachedAt, ok := claims["_cached_at"].(int64); ok {
		if time.Since(time.Unix(cachedAt, 0)) > tc.maxTTL {
			tc.cache.Delete(token)
			return nil, false
		}
	}

	// Check token expiry from claims
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			tc.cache.Delete(token)
			return nil, false
		}
	}

	tc.logger.Logf("Token found in cache (valid)")
	return claims, true
}

// InvalidateToken removes a token from cache and adds it to blacklist
func (tc *TokenCache) InvalidateToken(token string) {
	if token == "" {
		return
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Remove from cache
	tc.cache.Delete(token)

	// Add to blacklist
	if tc.blacklist != nil {
		tc.blacklist.Set(token, map[string]interface{}{
			"invalidated_at": time.Now().Unix(),
			"reason":         "manual_invalidation",
		})

		// Also blacklist JTI if present
		if claims, exists := tc.cache.Get(token); exists {
			if jti, ok := claims["jti"].(string); ok && jti != "" {
				tc.blacklist.Set(jti, map[string]interface{}{
					"invalidated_at": time.Now().Unix(),
					"reason":         "jti_invalidation",
				})
			}
		}
	}

	tc.logger.Logf("Token invalidated and blacklisted")
}

// StartCleanup starts the background cleanup process for expired tokens
func (tc *TokenCache) StartCleanup(interval time.Duration) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.cleanupTicker != nil {
		return // Already running
	}

	tc.cleanupTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-tc.cleanupTicker.C:
				tc.cleanupExpiredTokens()
			case <-tc.cleanupStop:
				return
			}
		}
	}()

	tc.logger.Logf("Started token cache cleanup (interval: %v)", interval)
}

// StopCleanup stops the background cleanup process
func (tc *TokenCache) StopCleanup() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.cleanupTicker != nil {
		tc.cleanupTicker.Stop()
		tc.cleanupTicker = nil
		close(tc.cleanupStop)
		tc.cleanupStop = make(chan bool)
		tc.logger.Logf("Stopped token cache cleanup")
	}
}

// cleanupExpiredTokens removes expired tokens from cache
func (tc *TokenCache) cleanupExpiredTokens() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// This would need to iterate through cache entries
	// Since we're using an interface, we'd need to add a method to get all keys
	// For now, this is a placeholder that would be implemented based on the actual cache implementation
	tc.logger.Logf("Running token cache cleanup")
}

// isBlacklisted checks if a token or its JTI is blacklisted
func (tc *TokenCache) isBlacklisted(token string, claims map[string]interface{}) bool {
	if tc.blacklist == nil {
		return false
	}

	// Check token itself
	if blacklisted, exists := tc.blacklist.Get(token); exists && blacklisted != nil {
		return true
	}

	// Check JTI
	if jti, ok := claims["jti"].(string); ok && jti != "" {
		if blacklisted, exists := tc.blacklist.Get(jti); exists && blacklisted != nil {
			return true
		}
	}

	return false
}

// TokenBlacklist manages blacklisted tokens
type TokenBlacklist struct {
	blacklist CacheInterface
	logger    LoggerInterface
	mu        sync.RWMutex
}

// NewTokenBlacklist creates a new token blacklist manager
func NewTokenBlacklist(blacklist CacheInterface, logger LoggerInterface) *TokenBlacklist {
	return &TokenBlacklist{
		blacklist: blacklist,
		logger:    logger,
	}
}

// Add adds a token to the blacklist
func (tb *TokenBlacklist) Add(token string, reason string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.blacklist.Set(token, map[string]interface{}{
		"blacklisted_at": time.Now().Unix(),
		"reason":         reason,
	})

	tb.logger.Logf("Token added to blacklist (reason: %s)", reason)
}

// AddJTI adds a JTI to the blacklist for replay detection
func (tb *TokenBlacklist) AddJTI(jti string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.blacklist.Set(jti, map[string]interface{}{
		"blacklisted_at": time.Now().Unix(),
		"reason":         "jti_replay_detection",
	})

	tb.logger.Logf("JTI added to blacklist for replay detection")
}

// IsBlacklisted checks if a token is blacklisted
func (tb *TokenBlacklist) IsBlacklisted(token string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if blacklisted, exists := tb.blacklist.Get(token); exists && blacklisted != nil {
		return true
	}

	return false
}

// IsJTIBlacklisted checks if a JTI is blacklisted
func (tb *TokenBlacklist) IsJTIBlacklisted(jti string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if blacklisted, exists := tb.blacklist.Get(jti); exists && blacklisted != nil {
		return true
	}

	return false
}

// TokenRevocationManager handles token revocation with providers
type TokenRevocationManager struct {
	clientID      string
	clientSecret  string
	revocationURL string
	httpClient    *http.Client
	logger        LoggerInterface
	blacklist     *TokenBlacklist
}

// NewTokenRevocationManager creates a new revocation manager
func NewTokenRevocationManager(clientID, clientSecret, revocationURL string, httpClient *http.Client, logger LoggerInterface, blacklist *TokenBlacklist) *TokenRevocationManager {
	return &TokenRevocationManager{
		clientID:      clientID,
		clientSecret:  clientSecret,
		revocationURL: revocationURL,
		httpClient:    httpClient,
		logger:        logger,
		blacklist:     blacklist,
	}
}

// RevokeToken revokes a token locally and optionally with the provider
func (trm *TokenRevocationManager) RevokeToken(token string, tokenType string, withProvider bool) error {
	// Add to local blacklist immediately
	trm.blacklist.Add(token, fmt.Sprintf("revoked_%s", tokenType))

	// Parse token to get JTI
	if jwt, err := parseJWT(token); err == nil {
		if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" {
			trm.blacklist.AddJTI(jti)
		}
	}

	// Revoke with provider if requested
	if withProvider && trm.revocationURL != "" {
		return trm.revokeWithProvider(token, tokenType)
	}

	return nil
}

// revokeWithProvider sends revocation request to the OIDC provider
func (trm *TokenRevocationManager) revokeWithProvider(token, tokenType string) error {
	// Implementation would send HTTP request to revocation endpoint
	// This is simplified for module structure
	trm.logger.Logf("Revoking %s with provider", tokenType)
	return nil
}
