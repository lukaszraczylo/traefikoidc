// Package token provides token verification and management functionality
package token

import (
	"fmt"
	"strings"
	"time"

	traefikoidc "github.com/lukaszraczylo/traefikoidc"
)

// Verifier handles token verification operations
type Verifier struct {
	tokenCache     TokenCache
	tokenBlacklist Cache
	jwkCache       JWKCache
	limiter        RateLimiter
	logger         Logger
}

// Cache interface for token operations
type Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
}

// TokenCache interface for verified token storage
type TokenCache interface {
	Get(key string) (map[string]interface{}, bool)
	Set(key string, claims map[string]interface{}, ttl time.Duration)
}

// JWKCache interface for key management
type JWKCache interface {
	GetJWKS(providerURL string) (*traefikoidc.JWKSet, error)
}

// RateLimiter interface for request limiting
type RateLimiter interface {
	Allow() bool
}

// Logger interface for logging
type Logger interface {
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// JWT represents a parsed JWT token
type JWT struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}

// NewVerifier creates a new token verifier
func NewVerifier(tokenCache TokenCache, tokenBlacklist Cache, jwkCache JWKCache, limiter RateLimiter, logger Logger) *Verifier {
	return &Verifier{
		tokenCache:     tokenCache,
		tokenBlacklist: tokenBlacklist,
		jwkCache:       jwkCache,
		limiter:        limiter,
		logger:         logger,
	}
}

// VerifyToken verifies the validity of an ID token or access token
func (v *Verifier) VerifyToken(token string, clientID string, jwksURL string, issuerURL string) error {
	if token == "" {
		return fmt.Errorf("invalid JWT format: token is empty")
	}

	if strings.Count(token, ".") != 2 {
		return fmt.Errorf("invalid JWT format: expected JWT with 3 parts, got %d parts", strings.Count(token, ".")+1)
	}

	if len(token) < 10 {
		return fmt.Errorf("token too short to be valid JWT")
	}

	// Check blacklist
	if v.tokenBlacklist != nil {
		if blacklisted, exists := v.tokenBlacklist.Get(token); exists && blacklisted != nil {
			return fmt.Errorf("token is blacklisted")
		}
	}

	// Check cache first
	if claims, exists := v.tokenCache.Get(token); exists && len(claims) > 0 {
		return nil
	}

	// Rate limiting
	if !v.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Parse and verify JWT
	jwt, err := v.parseJWT(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	if err := v.verifyJWTSignatureAndClaims(jwt, token, clientID, jwksURL, issuerURL); err != nil {
		return err
	}

	// Cache successful verification
	v.cacheVerifiedToken(token, jwt.Claims)

	return nil
}

// parseJWT parses a JWT token into its components
func (v *Verifier) parseJWT(token string) (*JWT, error) {
	// This would contain the actual JWT parsing logic
	// For now, return a placeholder
	return &JWT{
		Header: make(map[string]interface{}),
		Claims: make(map[string]interface{}),
	}, nil
}

// verifyJWTSignatureAndClaims verifies JWT signature and claims
func (v *Verifier) verifyJWTSignatureAndClaims(jwt *JWT, token string, clientID string, jwksURL string, issuerURL string) error {
	// This would contain the actual signature verification logic
	// For now, return nil (placeholder)
	return nil
}

// cacheVerifiedToken stores a successfully verified token
func (v *Verifier) cacheVerifiedToken(token string, claims map[string]interface{}) {
	if expClaim, ok := claims["exp"].(float64); ok {
		expirationTime := time.Unix(int64(expClaim), 0)
		duration := time.Until(expirationTime)
		if duration > 0 {
			v.tokenCache.Set(token, claims, duration)
		}
	}
}
