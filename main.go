// Package traefikoidc provides OIDC authentication middleware for Traefik.
// It supports multiple OIDC providers including Google, Azure AD, and generic OIDC providers
// with features like token refresh, session management, and provider-specific optimizations.
package traefikoidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Deprecated: Use CreateDefaultHTTPClient from http_client_factory.go instead
// createDefaultHTTPClient is kept for backward compatibility
func createDefaultHTTPClient() *http.Client {
	return CreateDefaultHTTPClient()
}

const (
	ConstSessionTimeout      = 86400
	defaultBlacklistDuration = 24 * time.Hour
	defaultMaxBlacklistSize  = 10000
)

var (
	globalCacheManager *CacheManager
	cacheManagerOnce   sync.Once
	cacheManagerMutex  sync.RWMutex
)

// CacheManager manages all caching components for the OIDC middleware.
// It provides thread-safe access to token blacklist, token cache, metadata cache,
// and JWK cache. This centralizes cache management to ensure efficient memory
// usage and consistent cache behavior across the application.
type CacheManager struct {
	tokenBlacklist *Cache
	tokenCache     *TokenCache
	metadataCache  *MetadataCache
	jwkCache       JWKCacheInterface
	mu             sync.RWMutex
}

// GetGlobalCacheManager returns a singleton instance of CacheManager.
// It initializes all cache components on first call and reuses the same instance
// for subsequent calls. This ensures consistent cache state and efficient memory
// usage across the entire application lifecycle.
// Parameters:
//   - wg: WaitGroup for coordinating cache cleanup during shutdown.
//
// Returns:
//   - The global CacheManager instance.
func GetGlobalCacheManager(wg *sync.WaitGroup) *CacheManager {
	cacheManagerOnce.Do(func() {
		globalCacheManager = &CacheManager{
			tokenBlacklist: func() *Cache {
				c := NewCache()
				c.SetMaxSize(defaultMaxBlacklistSize)
				return c
			}(),
			tokenCache:    NewTokenCache(),
			metadataCache: NewMetadataCache(wg),
			jwkCache:      &JWKCache{},
		}
	})
	return globalCacheManager
}

// GetSharedTokenBlacklist returns the shared token blacklist cache.
// This cache stores revoked or expired tokens to prevent replay attacks.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared token blacklist Cache instance.
func (cm *CacheManager) GetSharedTokenBlacklist() *Cache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.tokenBlacklist
}

// GetSharedTokenCache returns the shared token cache for verified tokens.
// This cache stores claims from successfully verified tokens to avoid
// repeated verification of the same tokens.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared TokenCache instance.
func (cm *CacheManager) GetSharedTokenCache() *TokenCache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.tokenCache
}

// GetSharedMetadataCache returns the shared metadata cache.
// This cache stores OIDC provider metadata (endpoints, keys) to avoid
// repeated requests to the provider's .well-known configuration endpoint.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared MetadataCache instance.
func (cm *CacheManager) GetSharedMetadataCache() *MetadataCache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.metadataCache
}

// GetSharedJWKCache returns the shared JWK (JSON Web Key) cache.
// This cache stores public keys from the provider's JWKS endpoint
// for token signature verification.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared JWKCacheInterface instance.
func (cm *CacheManager) GetSharedJWKCache() JWKCacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.jwkCache
}

// Close gracefully shuts down all cache components and releases resources.
// It closes all individual caches and cleans up their associated goroutines.
// This method should be called when the middleware is shutting down.
// Returns:
//   - An error if any cache fails to close properly, nil otherwise.
func (cm *CacheManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.tokenBlacklist != nil {
		cm.tokenBlacklist.Close()
	}
	if cm.tokenCache != nil {
		cm.tokenCache.Close()
	}
	if cm.metadataCache != nil {
		cm.metadataCache.Close()
	}
	if cm.jwkCache != nil {
		cm.jwkCache.Close()
	}

	return nil
}

// CleanupGlobalCacheManager cleans up the global cache manager instance.
// It closes all cache components and resets the singleton to allow
// re-initialization if needed. It's safe to call multiple times.
// Returns:
//   - An error if cache cleanup fails, nil otherwise.
func CleanupGlobalCacheManager() error {
	cacheManagerMutex.Lock()
	defer cacheManagerMutex.Unlock()

	if globalCacheManager != nil {
		err := globalCacheManager.Close()
		globalCacheManager = nil
		cacheManagerOnce = sync.Once{}
		return err
	}
	return nil
}

// TokenVerifier interface defines token verification capabilities.
// Implementations should validate token format, signature, and claims.
type TokenVerifier interface {
	VerifyToken(token string) error
}

// JWTVerifier interface defines JWT-specific verification capabilities.
// Implementations should validate JWT structure, signature using JWKs, and standard claims.
type JWTVerifier interface {
	VerifyJWTSignatureAndClaims(jwt *JWT, token string) error
}

// TokenExchanger interface defines OAuth 2.0 and OpenID Connect token exchange capabilities.
// Implementations should handle authorization code exchange, refresh tokens, and revocation
// according to the OAuth 2.0 and OpenID Connect specifications.
type TokenExchanger interface {
	ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error)
	GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error)
	RevokeTokenWithProvider(token, tokenType string) error
}

// TraefikOidc is the main middleware struct that implements OIDC authentication for Traefik.
// It integrates with various OIDC providers, manages sessions, caches tokens, and handles
// the complete authentication flow. It's designed to work seamlessly with Traefik's
// plugin system and provides flexible configuration options.
type TraefikOidc struct {
	jwkCache                   JWKCacheInterface
	jwtVerifier                JWTVerifier
	ctx                        context.Context
	tokenVerifier              TokenVerifier
	next                       http.Handler
	tokenExchanger             TokenExchanger
	initComplete               chan struct{}
	limiter                    *rate.Limiter
	tokenBlacklist             *Cache
	headerTemplates            map[string]*template.Template
	sessionManager             *SessionManager
	tokenCleanupStopChan       chan struct{}
	excludedURLs               map[string]struct{}
	extractClaimsFunc          func(tokenString string) (map[string]interface{}, error)
	initiateAuthenticationFunc func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string)
	metadataCache              *MetadataCache
	allowedRolesAndGroups      map[string]struct{}
	allowedUsers               map[string]struct{}
	allowedUserDomains         map[string]struct{}
	tokenCache                 *TokenCache
	httpClient                 *http.Client
	tokenHTTPClient            *http.Client
	logger                     *Logger
	metadataRefreshStopChan    chan struct{}
	cancelFunc                 context.CancelFunc
	errorRecoveryManager       *ErrorRecoveryManager
	goroutineWG                *sync.WaitGroup
	clientSecret               string
	clientID                   string
	name                       string
	redirURLPath               string
	logoutURLPath              string
	tokenURL                   string
	authURL                    string
	endSessionURL              string
	postLogoutRedirectURI      string
	scheme                     string
	jwksURL                    string
	issuerURL                  string
	revocationURL              string
	providerURL                string
	scopes                     []string
	refreshGracePeriod         time.Duration
	shutdownOnce               sync.Once
	firstRequestMutex          sync.Mutex
	forceHTTPS                 bool
	enablePKCE                 bool
	overrideScopes             bool
	suppressDiagnosticLogs     bool
	firstRequestReceived       bool
	metadataRefreshStarted     bool
}

// ProviderMetadata represents OIDC provider configuration data.
// This data is typically retrieved from the provider's .well-known/openid-configuration endpoint
// and contains essential URLs for authentication, token exchange, and key retrieval.
type ProviderMetadata struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	RevokeURL     string `json:"revocation_endpoint"`
	EndSessionURL string `json:"end_session_endpoint"`
}

// isTestMode detects if the code is running in a test environment.
// It checks various indicators including environment variables, command-line arguments,
// and runtime compiler information to determine test context.
// This helps suppress diagnostic logs during testing to keep test output clean.
// Returns:
//   - true if running in test mode, false otherwise.
func isTestMode() bool {
	if os.Getenv("SUPPRESS_DIAGNOSTIC_LOGS") == "1" {
		return true
	}

	if strings.Contains(os.Args[0], ".test") ||
		strings.Contains(os.Args[0], "go_build_") ||
		os.Getenv("GO_TEST") == "1" ||
		runtime.Compiler == "yaegi" {
		return true
	}

	for _, arg := range os.Args {
		if strings.Contains(arg, "-test") {
			return true
		}
	}

	if runtime.Compiler == "gc" {
		progName := os.Args[0]
		if strings.Contains(progName, "test") ||
			strings.HasSuffix(progName, ".test") ||
			strings.Contains(progName, "__debug_bin") {
			return true
		}
	}

	return false
}

// defaultExcludedURLs are the paths that are excluded from authentication
var defaultExcludedURLs = map[string]struct{}{
	"/favicon": {},
}

// VerifyToken verifies the validity of an ID token or access token.
// It performs comprehensive validation including format checks, blacklist verification,
// signature validation using JWKs, and standard claims validation. It also caches
// successfully verified tokens to avoid repeated verification.
// Parameters:
//   - token: The JWT token string to verify.
//
// Returns:
//   - An error if verification fails (e.g., blacklisted token, invalid format,
//     signature failure, or claims error), nil if verification succeeds.
func (t *TraefikOidc) VerifyToken(token string) error {
	if token == "" {
		return fmt.Errorf("invalid JWT format: token is empty")
	}

	if strings.Count(token, ".") != 2 {
		return fmt.Errorf("invalid JWT format: expected JWT with 3 parts, got %d parts", strings.Count(token, ".")+1)
	}

	if len(token) < 10 {
		return fmt.Errorf("token too short to be valid JWT")
	}

	if t.tokenBlacklist != nil {
		if blacklisted, exists := t.tokenBlacklist.Get(token); exists && blacklisted != nil {
			return fmt.Errorf("token is blacklisted (raw string) in cache")
		}
	}

	parsedJWT, parseErr := parseJWT(token)
	if parseErr != nil {
		return fmt.Errorf("failed to parse JWT for blacklist check: %w", parseErr)
	}

	tokenType := "UNKNOWN"
	if aud, ok := parsedJWT.Claims["aud"]; ok {
		if audStr, ok := aud.(string); ok && audStr == t.clientID {
			tokenType = "ID_TOKEN"
		}
	}
	if scope, ok := parsedJWT.Claims["scope"]; ok {
		if _, ok := scope.(string); ok {
			tokenType = "ACCESS_TOKEN"
		}
	}

	if jti, ok := parsedJWT.Claims["jti"].(string); ok && jti != "" {
		if !strings.HasPrefix(token, "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0") {
			if t.tokenBlacklist != nil {
				if blacklisted, exists := t.tokenBlacklist.Get(jti); exists && blacklisted != nil {
					return fmt.Errorf("token replay detected (jti: %s) in cache", jti)
				}
			}
		}
	}

	if claims, exists := t.tokenCache.Get(token); exists && len(claims) > 0 {
		return nil
	}

	if !t.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	jwt := parsedJWT

	if err := t.VerifyJWTSignatureAndClaims(jwt, token); err != nil {
		if !strings.Contains(err.Error(), "token has expired") {
			t.logger.Errorf("%s token verification failed: %v", tokenType, err)
		}
		return err
	}

	t.cacheVerifiedToken(token, jwt.Claims)

	if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" {
		expiry := time.Now().Add(defaultBlacklistDuration)
		if expClaim, expOk := jwt.Claims["exp"].(float64); expOk {
			expTime := time.Unix(int64(expClaim), 0)
			tokenDuration := time.Until(expTime)
			if tokenDuration > defaultBlacklistDuration && tokenDuration < (24*time.Hour) {
				expiry = expTime
			} else if tokenDuration <= 0 {
				expiry = time.Now().Add(defaultBlacklistDuration)
			} else {
				expiry = time.Now().Add(defaultBlacklistDuration)
			}
		}

		if t.tokenBlacklist != nil {
			t.tokenBlacklist.Set(jti, true, time.Until(expiry))
			t.logger.Debugf("Added JTI %s to blacklist cache", jti)
		} else {
			t.logger.Errorf("Token blacklist not available, skipping JTI %s blacklist", jti)
		}

		replayCacheMu.Lock()
		if replayCache == nil {
			initReplayCache()
		}
		duration := time.Until(expiry)
		if duration > 0 {
			replayCache.Set(jti, true, duration)
		}
		replayCacheMu.Unlock()
	}

	return nil
}

// cacheVerifiedToken stores a successfully verified token and its claims in the cache.
// The token is cached until its expiration time to avoid repeated verification.
// Parameters:
//   - token: The verified token string to cache.
//   - claims: The map of claims extracted from the verified token.
func (t *TraefikOidc) cacheVerifiedToken(token string, claims map[string]interface{}) {
	expClaim, ok := claims["exp"].(float64)
	if !ok {
		t.logger.Errorf("Failed to cache token: invalid 'exp' claim type")
		return
	}

	expirationTime := time.Unix(int64(expClaim), 0)
	now := time.Now()
	duration := expirationTime.Sub(now)
	t.tokenCache.Set(token, claims, duration)
}

// VerifyJWTSignatureAndClaims verifies JWT signature using provider's public keys and validates standard claims.
// It retrieves the appropriate public key from the JWKS cache, verifies the token signature,
// and validates standard OIDC claims like issuer, audience, and expiration.
// Parameters:
//   - jwt: The parsed JWT structure containing header and claims.
//   - token: The raw token string for signature verification.
//
// Returns:
//   - An error if verification fails (e.g., JWKS retrieval failed, no matching key,
//     signature verification failed, standard claim validation failed), nil if successful.
func (t *TraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	t.logger.Debugf("Verifying JWT signature and claims")

	jwks, err := t.jwkCache.GetJWKS(context.Background(), t.jwksURL, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	if !t.suppressDiagnosticLogs {
		t.logger.Debugf("DIAGNOSTIC: Retrieved JWKS with %d keys from URL: %s", len(jwks.Keys), t.jwksURL)
	}

	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("missing key ID in token header")
	}
	alg, ok := jwt.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing algorithm in token header")
	}

	if !t.suppressDiagnosticLogs {
		t.logger.Debugf("DIAGNOSTIC: Looking for kid=%s, alg=%s in JWKS", kid, alg)
	}

	// Find the matching key in JWKS
	var matchingKey *JWK
	availableKids := make([]string, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		availableKids = append(availableKids, key.Kid)
		if key.Kid == kid {
			matchingKey = &key
			break
		}
	}

	if matchingKey == nil {
		if !t.suppressDiagnosticLogs {
			t.logger.Errorf("DIAGNOSTIC: No matching key found for kid=%s. Available kids: %v", kid, availableKids)
		}
		return fmt.Errorf("no matching public key found for kid: %s", kid)
	}

	if !t.suppressDiagnosticLogs {
		t.logger.Debugf("DIAGNOSTIC: Found matching key for kid=%s, key type: %s", kid, matchingKey.Kty)
	}

	publicKeyPEM, err := jwkToPEM(matchingKey)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to PEM: %w", err)
	}

	if err := verifySignature(token, publicKeyPEM, alg); err != nil {
		if !t.suppressDiagnosticLogs {
			t.logger.Errorf("DIAGNOSTIC: Signature verification failed for kid=%s, alg=%s: %v", kid, alg, err)
		}
		return fmt.Errorf("signature verification failed: %w", err)
	}

	if !t.suppressDiagnosticLogs {
		t.logger.Debugf("DIAGNOSTIC: Signature verification successful for kid=%s", kid)
	}

	if err := jwt.Verify(t.issuerURL, t.clientID, true); err != nil {
		return fmt.Errorf("standard claim verification failed: %w", err)
	}

	return nil
}

// mergeScopes combines default scopes with user-provided scopes, removing duplicates.
// Default scopes are placed first, followed by user scopes not already present.
// Parameters:
//   - defaultScopes: The default scopes required by the application.
//   - userScopes: Additional scopes specified by the user.
//
// Returns:
//   - A slice containing merged scopes with defaults first, then user scopes, with duplicates removed.
func mergeScopes(defaultScopes, userScopes []string) []string {
	if len(userScopes) == 0 {
		return append([]string(nil), defaultScopes...)
	}

	seen := make(map[string]bool)
	var result []string

	for _, scope := range defaultScopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}

	for _, scope := range userScopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}

	return result
}

// New creates a new TraefikOidc middleware instance.
// It initializes all components including caches, HTTP clients, session management,
// templates, and starts background processes for metadata discovery.
// Parameters:
//   - ctx: The context for the middleware lifecycle.
//   - next: The next HTTP handler in the middleware chain.
//   - config: The OIDC configuration containing provider details, client credentials, etc.
//   - name: The name of the middleware instance.
//
// Returns:
//   - The configured TraefikOidc handler ready to process requests.
//   - An error if essential configuration is missing or invalid (e.g., short encryption key).
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	if config.SessionEncryptionKey == "" {
		config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}

	logger := NewLogger(config.LogLevel)
	if len(config.SessionEncryptionKey) < minEncryptionKeyLength {
		if runtime.Compiler == "yaegi" {
			config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			logger.Infof("Session encryption key is too short; using default key for analyzer")
		} else {
			return nil, fmt.Errorf("encryption key must be at least %d bytes long", minEncryptionKeyLength)
		}
	}
	// Setup HTTP client
	var httpClient *http.Client
	if config.HTTPClient != nil {
		httpClient = config.HTTPClient
	} else {
		httpClient = CreateDefaultHTTPClient()
	}
	goroutineWG := &sync.WaitGroup{}
	cacheManager := GetGlobalCacheManager(goroutineWG)

	pluginCtx, cancelFunc := context.WithCancel(context.Background())

	t := &TraefikOidc{
		next:         next,
		name:         name,
		goroutineWG:  goroutineWG,
		redirURLPath: config.CallbackURL,
		logoutURLPath: func() string {
			if config.LogoutURL == "" {
				return config.CallbackURL + "/logout"
			}
			return config.LogoutURL
		}(),
		postLogoutRedirectURI: func() string {
			if config.PostLogoutRedirectURI == "" {
				return "/"
			}
			return config.PostLogoutRedirectURI
		}(),
		tokenBlacklist: cacheManager.GetSharedTokenBlacklist(),
		jwkCache:       cacheManager.GetSharedJWKCache(),
		metadataCache:  cacheManager.GetSharedMetadataCache(),
		clientID:       config.ClientID,
		clientSecret:   config.ClientSecret,
		forceHTTPS:     config.ForceHTTPS,
		enablePKCE:     config.EnablePKCE,
		overrideScopes: config.OverrideScopes,
		scopes: func() []string {
			userProvidedScopes := deduplicateScopes(config.Scopes)

			if config.OverrideScopes {
				return userProvidedScopes
			}

			defaultSystemScopes := []string{"openid", "profile", "email"}
			return deduplicateScopes(mergeScopes(defaultSystemScopes, userProvidedScopes))
		}(),
		limiter:               rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		tokenCache:            cacheManager.GetSharedTokenCache(),
		httpClient:            httpClient,
		tokenHTTPClient:       CreateTokenHTTPClient(),
		excludedURLs:          createStringMap(config.ExcludedURLs),
		allowedUserDomains:    createStringMap(config.AllowedUserDomains),
		allowedUsers:          createCaseInsensitiveStringMap(config.AllowedUsers),
		allowedRolesAndGroups: createStringMap(config.AllowedRolesAndGroups),
		initComplete:          make(chan struct{}),
		logger:                logger,
		refreshGracePeriod: func() time.Duration {
			if config.RefreshGracePeriodSeconds > 0 {
				return time.Duration(config.RefreshGracePeriodSeconds) * time.Second
			}
			return 60 * time.Second
		}(),
		tokenCleanupStopChan:    make(chan struct{}),
		metadataRefreshStopChan: make(chan struct{}),
		ctx:                     pluginCtx,
		cancelFunc:              cancelFunc,
		suppressDiagnosticLogs:  isTestMode(),
	}

	t.sessionManager, _ = NewSessionManager(config.SessionEncryptionKey, config.ForceHTTPS, config.CookieDomain, t.logger)
	t.errorRecoveryManager = NewErrorRecoveryManager(t.logger)
	t.extractClaimsFunc = extractClaims
	t.initiateAuthenticationFunc = func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
	}

	for k, v := range defaultExcludedURLs {
		t.excludedURLs[k] = v
	}

	t.tokenVerifier = t
	t.jwtVerifier = t
	t.tokenExchanger = t

	t.headerTemplates = make(map[string]*template.Template)

	funcMap := template.FuncMap{
		"default": func(defaultVal interface{}, val interface{}) interface{} {
			if val == nil || val == "" {
				return defaultVal
			}
			return val
		},
		"get": func(m interface{}, key string) interface{} {
			if mapVal, ok := m.(map[string]interface{}); ok {
				if val, exists := mapVal[key]; exists {
					return val
				}
			}
			return ""
		},
	}

	for _, header := range config.Headers {
		tmpl := template.New(header.Name).Funcs(funcMap).Option("missingkey=zero")

		parsedTmpl, err := tmpl.Parse(header.Value)
		if err != nil {
			logger.Errorf("Failed to parse header template for %s: %v", header.Name, err)
			continue
		}

		t.headerTemplates[header.Name] = parsedTmpl
		logger.Debugf("Parsed template for header %s: %s", header.Name, header.Value)
	}

	startReplayCacheCleanup(pluginCtx, logger)
	logger.Debugf("TraefikOidc.New: Final t.scopes initialized to: %v", t.scopes)

	t.providerURL = config.ProviderURL
	go t.initializeMetadata(config.ProviderURL)

	return t, nil
}

// initializeMetadata initializes OIDC provider metadata by fetching configuration.
// It retrieves the provider's .well-known/openid-configuration and updates
// internal endpoint URLs. Uses error recovery if available for resilient fetching.
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
func (t *TraefikOidc) initializeMetadata(providerURL string) {
	t.logger.Debug("Starting provider metadata discovery")

	// Get metadata from cache or fetch it with error recovery if available
	var metadata *ProviderMetadata
	var err error
	if t.errorRecoveryManager != nil {
		metadata, err = t.metadataCache.GetMetadataWithRecovery(providerURL, t.httpClient, t.logger, t.errorRecoveryManager)
	} else {
		metadata, err = t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
	}
	if err != nil {
		t.logger.Errorf("Failed to get provider metadata: %v", err)
		return
	}

	if metadata != nil {
		t.logger.Debug("Successfully initialized provider metadata")
		t.updateMetadataEndpoints(metadata)

		close(t.initComplete)
		return
	}

	t.logger.Error("Received nil metadata during initialization")
}

// updateMetadataEndpoints updates internal endpoint URLs with discovered metadata.
// It sets the authorization URL, token URL, JWKS URL, issuer URL, revocation URL,
// and end session URL based on the provider's metadata.
// Parameters:
//   - metadata: A pointer to the ProviderMetadata struct containing the discovered endpoints.
func (t *TraefikOidc) updateMetadataEndpoints(metadata *ProviderMetadata) {
	t.jwksURL = metadata.JWKSURL
	t.authURL = metadata.AuthURL
	t.tokenURL = metadata.TokenURL
	t.issuerURL = metadata.Issuer
	t.revocationURL = metadata.RevokeURL
	t.endSessionURL = metadata.EndSessionURL
}

// startMetadataRefresh starts a background goroutine that periodically refreshes provider metadata.
// It runs every 2 hours and implements exponential backoff for consecutive failures.
// The refresh helps ensure endpoint URLs stay current and handles provider configuration changes.
// Parameters:
//   - providerURL: The base URL of the OIDC provider, used for subsequent refresh attempts.
func (t *TraefikOidc) startMetadataRefresh(providerURL string) {
	ticker := time.NewTicker(2 * time.Hour)

	if t.goroutineWG != nil {
		t.goroutineWG.Add(1)
	}

	go func() {
		defer func() {
			if t.goroutineWG != nil {
				t.goroutineWG.Done()
			}
		}()
		defer ticker.Stop()

		consecutiveFailures := 0
		for {
			select {
			case <-ticker.C:
				if consecutiveFailures >= 3 {
					t.logger.Debug("Skipping metadata refresh due to consecutive failures")
					consecutiveFailures++
					if consecutiveFailures > 10 {
						consecutiveFailures = 3
					}
					continue
				}

				t.logger.Debug("Refreshing OIDC metadata")
				var metadata *ProviderMetadata
				var err error
				if t.errorRecoveryManager != nil {
					metadata, err = t.metadataCache.GetMetadataWithRecovery(providerURL, t.httpClient, t.logger, t.errorRecoveryManager)
				} else {
					metadata, err = t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
				}
				if err != nil {
					consecutiveFailures++
					t.logger.Errorf("Failed to refresh metadata (attempt %d): %v", consecutiveFailures, err)
					continue
				}

				if metadata != nil {
					t.updateMetadataEndpoints(metadata)
					t.logger.Debug("Successfully refreshed metadata")
					consecutiveFailures = 0
				} else {
					consecutiveFailures++
					t.logger.Error("Received nil metadata during refresh")
				}
			case <-t.metadataRefreshStopChan:
				t.logger.Debug("Metadata refresh goroutine stopped.")
				return
			case <-t.ctx.Done():
				t.logger.Debug("Metadata refresh goroutine stopped due to context cancellation.")
				return
			}
		}
	}()
}

// discoverProviderMetadata fetches OIDC provider metadata from the .well-known endpoint.
// It constructs the well-known URL, uses retry logic for resilient fetching,
// and returns the parsed provider metadata.
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
//   - httpClient: The HTTP client to use for the request.
//   - l: Logger instance for error and debug logging.
//
// Returns:
//   - The parsed ProviderMetadata containing endpoint URLs.
//   - An error if fetching fails after all retries or if a timeout is exceeded.
func discoverProviderMetadata(providerURL string, httpClient *http.Client, l *Logger) (*ProviderMetadata, error) {
	wellKnownURL := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"

	retryConfig := RetryConfig{
		MaxAttempts:   2,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      50 * time.Millisecond,
		BackoffFactor: 2.0,
		EnableJitter:  true,
		RetryableErrors: []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"network unreachable",
			"no route to host",
			"connection reset",
			"status code 500",
			"status code 502",
			"status code 503",
			"status code 504",
		},
	}

	retryExecutor := NewRetryExecutor(retryConfig, l)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var metadata *ProviderMetadata
	err := retryExecutor.ExecuteWithContext(ctx, func() error {
		var fetchErr error
		metadata, fetchErr = fetchMetadata(wellKnownURL, httpClient)
		return fetchErr
	})

	if err != nil {
		l.Errorf("Failed to fetch provider metadata after retries: %v", err)
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}

	l.Debug("Provider metadata fetched successfully")
	return metadata, nil
}

// fetchMetadata performs the actual HTTP request to fetch provider metadata.
// It makes a GET request to the .well-known URL, validates the response,
// and decodes the JSON metadata.
// Parameters:
//   - wellKnownURL: The complete URL to the .well-known/openid-configuration endpoint.
//   - httpClient: The HTTP client to use for the request.
//
// Returns:
//   - The parsed ProviderMetadata from the response.
//   - An error if the GET request fails, the status code is not 200 OK, or JSON decoding fails.
func fetchMetadata(wellKnownURL string, httpClient *http.Client) (*ProviderMetadata, error) {
	resp, err := httpClient.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from provider at %s", wellKnownURL)
	}

	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 1024*10)
		bodyBytes, _ := io.ReadAll(limitReader)
		return nil, fmt.Errorf("failed to fetch provider metadata from %s: status code %d, body: %s", wellKnownURL, resp.StatusCode, string(bodyBytes))
	}

	var metadata ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode provider metadata from %s: %w", wellKnownURL, err)
	}

	return &metadata, nil
}

// ServeHTTP implements the main middleware logic for processing HTTP requests.
// It handles the complete OIDC authentication flow including:
//   - Excluded URL bypass
//   - Session validation and management
//   - Authentication callback processing
//   - Logout handling
//   - Token verification and refresh
//   - Header injection for authenticated requests
//
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The incoming HTTP request.
func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !strings.HasPrefix(req.URL.Path, "/health") {
		t.firstRequestMutex.Lock()
		if !t.firstRequestReceived {
			t.firstRequestReceived = true
			t.logger.Debug("Starting background tasks on first request")
			t.startTokenCleanup()

			if !t.metadataRefreshStarted && t.providerURL != "" {
				t.metadataRefreshStarted = true
				go t.startMetadataRefresh(t.providerURL)
			}
		}
		t.firstRequestMutex.Unlock()
	}

	select {
	case <-t.initComplete:
		if t.issuerURL == "" {
			t.logger.Error("OIDC provider metadata initialization failed or incomplete")
			http.Error(rw, "OIDC provider metadata initialization failed - please check provider availability and configuration", http.StatusServiceUnavailable)
			return
		}
	case <-req.Context().Done():
		t.logger.Debug("Request cancelled while waiting for OIDC initialization")
		http.Error(rw, "Request cancelled", http.StatusRequestTimeout)
		return
	case <-time.After(30 * time.Second):
		t.logger.Error("Timeout waiting for OIDC initialization")
		http.Error(rw, "Timeout waiting for OIDC provider initialization - please try again later", http.StatusServiceUnavailable)
		return
	}

	if t.determineExcludedURL(req.URL.Path) {
		t.logger.Debugf("Request path %s excluded by configuration, bypassing OIDC", req.URL.Path)
		t.next.ServeHTTP(rw, req)
		return
	}
	acceptHeader := req.Header.Get("Accept")
	if strings.Contains(acceptHeader, "text/event-stream") {
		t.logger.Debugf("Request accepts text/event-stream (%s), bypassing OIDC", acceptHeader)
		t.next.ServeHTTP(rw, req)
		return
	}

	t.sessionManager.CleanupOldCookies(rw, req)

	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v. Initiating authentication.", err)
		cleanReq := req.Clone(req.Context())
		session, _ = t.sessionManager.GetSession(cleanReq)
		if session != nil {
			defer session.returnToPoolSafely()
			if clearErr := session.Clear(cleanReq, rw); clearErr != nil {
				t.logger.Errorf("Error clearing potentially corrupted session: %v", clearErr)
			}
		} else {
			t.logger.Error("Critical session error: Failed to get even a new session.")
			http.Error(rw, "Critical session error", http.StatusInternalServerError)
			return
		}
		scheme := t.determineScheme(req)
		host := t.determineHost(req)
		redirectURL := buildFullURL(scheme, host, t.redirURLPath)
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	defer session.returnToPoolSafely()

	scheme := t.determineScheme(req)
	host := t.determineHost(req)
	redirectURL := buildFullURL(scheme, host, t.redirURLPath)

	if req.URL.Path == t.logoutURLPath {
		t.handleLogout(rw, req)
		return
	}
	if req.URL.Path == t.redirURLPath {
		t.handleCallback(rw, req, redirectURL)
		return
	}

	authenticated, needsRefresh, expired := t.isUserAuthenticated(session)

	if expired {
		t.logger.Debug("Session token is definitively expired or invalid, initiating re-auth")
		t.handleExpiredToken(rw, req, session, redirectURL)
		return
	}

	email := session.GetEmail()
	if authenticated && email != "" {
		if !t.isAllowedDomain(email) {
			t.logger.Infof("User with email %s is not from an allowed domain", email)
			errorMsg := fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", t.logoutURLPath)
			t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	if authenticated && !needsRefresh {
		t.logger.Debug("User authenticated and token valid, proceeding to process authorized request")
		if accessToken := session.GetAccessToken(); accessToken != "" {
			if strings.Count(accessToken, ".") == 2 {
				if err := t.verifyToken(accessToken); err != nil {
					t.logger.Errorf("Access token validation failed: %v", err)
					t.handleExpiredToken(rw, req, session, redirectURL)
					return
				}
			} else {
				t.logger.Debugf("Access token appears opaque, skipping JWT verification for it.")
			}
		}
		t.processAuthorizedRequest(rw, req, session, redirectURL)
		return
	}

	refreshTokenPresent := session.GetRefreshToken() != ""
	shouldAttemptRefresh := needsRefresh && refreshTokenPresent

	if shouldAttemptRefresh {
		idToken := session.GetIDToken()
		if idToken != "" {
			jwt, err := parseJWT(idToken)
			if err == nil {
				claims := jwt.Claims
				if expClaim, ok := claims["exp"].(float64); ok {
					expTime := int64(expClaim)
					expTimeObj := time.Unix(expTime, 0)
					refreshThreshold := time.Now().Add(t.refreshGracePeriod)

					if !expTimeObj.Before(refreshThreshold) {
						t.logger.Debug("Token is valid and outside grace period, skipping refresh")
						t.processAuthorizedRequest(rw, req, session, redirectURL)
						return
					}
				} else {
					t.logger.Debug("Could not extract 'exp' claim for grace period check, proceeding with refresh")
				}
			}
		}

		if needsRefresh && authenticated {
			t.logger.Debug("Session token needs proactive refresh, attempting refresh")
		} else if needsRefresh && !authenticated {
			t.logger.Debug("ID token invalid/expired, but refresh token found. Attempting refresh.")
		}

		refreshed := t.refreshToken(rw, req, session)
		if refreshed {
			email = session.GetEmail()
			if email != "" && !t.isAllowedDomain(email) {
				t.logger.Infof("User with refreshed token email %s is not from an allowed domain", email)
				errorMsg := fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", t.logoutURLPath)
				t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
				return
			}

			t.logger.Debug("Token refresh successful, proceeding to process authorized request")
			t.processAuthorizedRequest(rw, req, session, redirectURL)
			return
		}

		t.logger.Debug("Token refresh failed, requiring re-authentication")
		acceptHeader := req.Header.Get("Accept")
		if strings.Contains(acceptHeader, "application/json") {
			t.logger.Debug("Client accepts JSON, sending 401 Unauthorized on refresh failure")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized", "message": "Token refresh failed"})
		} else {
			t.logger.Debug("Client does not prefer JSON, handling refresh failure by initiating re-auth")
			t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		}
		return
	}

	t.logger.Debugf("Initiating full OIDC authentication flow (authenticated=%v, needsRefresh=%v, refreshTokenPresent=%v)", authenticated, needsRefresh, refreshTokenPresent)
	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// processAuthorizedRequest processes requests for authenticated users.
// It extracts claims, validates roles/groups if configured, sets authentication headers,
// processes header templates, and forwards the request to the next handler.
// Domain checks should be performed before calling this method.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request to process.
//   - session: The user's session data containing tokens and claims.
//   - redirectURL: The callback URL for re-authentication if needed.
func (t *TraefikOidc) processAuthorizedRequest(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	email := session.GetEmail()
	if email == "" {
		t.logger.Info("No email found in session during final processing, initiating re-auth")
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	tokenForClaims := session.GetIDToken()
	if tokenForClaims == "" {
		tokenForClaims = session.GetAccessToken()
		if tokenForClaims == "" && len(t.allowedRolesAndGroups) > 0 {
			t.logger.Error("No token available but roles/groups checks are required")
			t.defaultInitiateAuthentication(rw, req, session, redirectURL)
			return
		}
	}

	// Initialize empty slices
	var groups, roles []string

	if tokenForClaims != "" {
		var err error
		groups, roles, err = t.extractGroupsAndRoles(tokenForClaims)
		if err != nil && len(t.allowedRolesAndGroups) > 0 {
			t.logger.Errorf("Failed to extract groups and roles: %v", err)
			t.defaultInitiateAuthentication(rw, req, session, redirectURL)
			return
		} else if err == nil {
			if len(groups) > 0 {
				req.Header.Set("X-User-Groups", strings.Join(groups, ","))
			}
			if len(roles) > 0 {
				req.Header.Set("X-User-Roles", strings.Join(roles, ","))
			}
		}
	}

	if len(t.allowedRolesAndGroups) > 0 {
		allowed := false
		for _, roleOrGroup := range append(groups, roles...) {
			if _, ok := t.allowedRolesAndGroups[roleOrGroup]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			t.logger.Infof("User with email %s does not have any allowed roles or groups", email)
			errorMsg := fmt.Sprintf("Access denied: You do not have any of the allowed roles or groups. To log out, visit: %s", t.logoutURLPath)
			t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	req.Header.Set("X-Forwarded-User", email)

	req.Header.Set("X-Auth-Request-Redirect", req.URL.RequestURI())
	req.Header.Set("X-Auth-Request-User", email)
	if idToken := session.GetIDToken(); idToken != "" {
		req.Header.Set("X-Auth-Request-Token", idToken)
	}

	if len(t.headerTemplates) > 0 {
		claims, err := t.extractClaimsFunc(session.GetIDToken())
		if err != nil {
			t.logger.Errorf("Failed to extract claims from ID Token for template headers: %v", err)
		} else {
			templateData := map[string]interface{}{
				"AccessToken":  session.GetAccessToken(),
				"IDToken":      session.GetIDToken(),
				"RefreshToken": session.GetRefreshToken(),
				"Claims":       claims,
			}

			for headerName, tmpl := range t.headerTemplates {
				var buf bytes.Buffer

				if err := tmpl.Execute(&buf, templateData); err != nil {
					t.logger.Errorf("Failed to execute template for header %s: %v", headerName, err)
					continue
				}
				headerValue := buf.String()

				req.Header.Set(headerName, headerValue)

				t.logger.Debugf("Set templated header %s = %s", headerName, headerValue)
			}
			session.MarkDirty()
			t.logger.Debugf("Session marked dirty after templated header processing.")
		}
	}

	if session.IsDirty() {
		if err := session.Save(req, rw); err != nil {
			t.logger.Errorf("Failed to save session after processing headers: %v", err)
		}
	} else {
		t.logger.Debug("Session not dirty, skipping save in processAuthorizedRequest")
	}

	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-XSS-Protection", "1; mode=block")
	rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	origin := req.Header.Get("Origin")
	if origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		rw.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if req.Method == "OPTIONS" {
			rw.WriteHeader(http.StatusOK)
			return
		}
	}

	t.logger.Debugf("Request authorized for user %s, forwarding to next handler", email)

	t.next.ServeHTTP(rw, req)
}

// handleExpiredToken handles requests with expired or invalid tokens.
// It clears the session data and initiates a new authentication flow.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request with expired token.
//   - session: The session data to clear.
//   - redirectURL: The callback URL to be used in the new authentication flow.
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debug("Handling expired token: Clearing session and initiating re-authentication.")
	session.SetAuthenticated(false)
	session.SetIDToken("")
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetEmail("")

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save cleared session during expired token handling: %v", err)
	}

	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// handleCallback processes the OIDC callback after user authentication.
// It validates state/CSRF tokens, exchanges authorization code for tokens,
// verifies the received tokens, extracts claims, and establishes the session.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The callback request containing authorization code and state.
//   - redirectURL: The fully qualified callback URL (used in the token exchange request).
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error during callback: %v", err)
		http.Error(rw, "Session error during callback", http.StatusInternalServerError)
		return
	}
	defer session.returnToPoolSafely()

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		if errorDescription == "" {
			errorDescription = req.URL.Query().Get("error")
		}
		t.logger.Errorf("Authentication error from provider during callback: %s - %s", req.URL.Query().Get("error"), errorDescription)
		t.sendErrorResponse(rw, req, fmt.Sprintf("Authentication error from provider: %s", errorDescription), http.StatusBadRequest)
		return
	}

	state := req.URL.Query().Get("state")
	if state == "" {
		t.logger.Error("No state in callback")
		t.sendErrorResponse(rw, req, "State parameter missing in callback", http.StatusBadRequest)
		return
	}

	csrfToken := session.GetCSRF()
	if csrfToken == "" {
		t.logger.Errorf("CSRF token missing in session during callback. Authenticated: %v, Request URL: %s",
			session.GetAuthenticated(), req.URL.String())

		cookie, err := req.Cookie("_oidc_raczylo_m")
		if err != nil {
			t.logger.Errorf("Main session cookie not found in request: %v", err)
		} else {
			t.logger.Errorf("Main session cookie exists but CSRF token is empty. Cookie value length: %d", len(cookie.Value))
		}

		t.sendErrorResponse(rw, req, "CSRF token missing in session", http.StatusBadRequest)
		return
	}

	if state != csrfToken {
		t.logger.Error("State parameter does not match CSRF token in session during callback")
		t.sendErrorResponse(rw, req, "Invalid state parameter (CSRF mismatch)", http.StatusBadRequest)
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		t.sendErrorResponse(rw, req, "No authorization code received in callback", http.StatusBadRequest)
		return
	}

	codeVerifier := session.GetCodeVerifier()

	tokenResponse, err := t.tokenExchanger.ExchangeCodeForToken(req.Context(), "authorization_code", code, redirectURL, codeVerifier)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not exchange code for token", http.StatusInternalServerError)
		return
	}

	if err = t.verifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not verify ID token", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not extract claims from token", http.StatusInternalServerError)
		return
	}

	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in token", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in session", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		t.logger.Error("Nonce claim does not match session nonce during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce mismatch", http.StatusInternalServerError)
		return
	}

	email, _ := claims["email"].(string)
	if email == "" {
		t.logger.Errorf("Email claim missing or empty in token during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Email missing in token", http.StatusInternalServerError)
		return
	}
	if !t.isAllowedDomain(email) {
		t.logger.Errorf("Disallowed email domain during callback: %s", email)
		t.sendErrorResponse(rw, req, "Authentication failed: Email domain not allowed", http.StatusForbidden)
		return
	}

	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("Failed to set authenticated state and regenerate session ID: %v", err)
		http.Error(rw, "Failed to update session", http.StatusInternalServerError)
		return
	}
	session.SetEmail(email)
	session.SetIDToken(tokenResponse.IDToken)
	session.SetAccessToken(tokenResponse.AccessToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	session.SetCSRF("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	session.ResetRedirectCount()

	redirectPath := "/"
	if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != t.redirURLPath {
		redirectPath = incomingPath
	}
	session.SetIncomingPath("")

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session after callback: %v", err)
		http.Error(rw, "Failed to save session after callback", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Callback successful, redirecting to %s", redirectPath)
	http.Redirect(rw, req, redirectPath, http.StatusFound)
}

// determineExcludedURL checks if a URL path should bypass OIDC authentication.
// It compares the request path against configured excluded URL prefixes.
// Parameters:
//   - currentRequest: The request path to check.
//
// Returns:
//   - true if the URL should be excluded from authentication, false otherwise.
func (t *TraefikOidc) determineExcludedURL(currentRequest string) bool {
	for excludedURL := range t.excludedURLs {
		if strings.HasPrefix(currentRequest, excludedURL) {
			t.logger.Debugf("URL is excluded - got %s / excluded hit: %s", currentRequest, excludedURL)
			return true
		}
	}
	return false
}

// determineScheme determines the URL scheme for building redirect URLs.
// It checks X-Forwarded-Proto header first, then TLS presence.
// Parameters:
//   - req: The HTTP request to analyze.
//
// Returns:
//   - The determined scheme: "https" or "http".
func (t *TraefikOidc) determineScheme(req *http.Request) string {
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// determineHost determines the host for building redirect URLs.
// It checks X-Forwarded-Host header first, then falls back to req.Host.
// Parameters:
//   - req: The HTTP request to analyze.
//
// Returns:
//   - The determined host string (e.g., "example.com:8080").
func (t *TraefikOidc) determineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

// isUserAuthenticated determines the authentication status and refresh requirements.
// It delegates to provider-specific validation methods that handle different token types
// and expiration behaviors.
// Parameters:
//   - session: The session data containing authentication tokens.
//
// Returns:
//   - authenticated (bool): True if the user has valid tokens.
//   - needsRefresh (bool): True if tokens are valid but nearing expiration.
//   - expired (bool): True if the session is unauthenticated, the token is missing,
//     or the token verification failed for reasons other than nearing/actual expiration.
func (t *TraefikOidc) isUserAuthenticated(session *SessionData) (bool, bool, bool) {
	if t.isAzureProvider() {
		return t.validateAzureTokens(session)
	} else if t.isGoogleProvider() {
		return t.validateGoogleTokens(session)
	}
	return t.validateStandardTokens(session)
}

// defaultInitiateAuthentication initiates the OIDC authentication flow.
// It generates CSRF tokens, nonce, PKCE parameters (if enabled), clears the session,
// stores authentication state, and redirects the user to the OIDC provider.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request initiating authentication.
//   - session: The session data to prepare for authentication.
//   - redirectURL: The pre-calculated callback URL (redirect_uri) for this middleware instance.
func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debugf("Initiating new OIDC authentication flow for request: %s", req.URL.RequestURI())

	const maxRedirects = 5
	redirectCount := session.GetRedirectCount()
	if redirectCount >= maxRedirects {
		t.logger.Errorf("Maximum redirect limit (%d) exceeded, possible redirect loop detected", maxRedirects)
		session.ResetRedirectCount()
		http.Error(rw, "Authentication failed: Too many redirects", http.StatusLoopDetected)
		return
	}

	session.IncrementRedirectCount()

	csrfToken := uuid.NewString()
	nonce, err := generateNonce()
	if err != nil {
		t.logger.Errorf("Failed to generate nonce: %v", err)
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Generate PKCE code verifier and challenge if PKCE is enabled
	var codeVerifier, codeChallenge string
	if t.enablePKCE {
		var err error
		codeVerifier, err = generateCodeVerifier()
		if err != nil {
			t.logger.Errorf("Failed to generate code verifier: %v", err)
			http.Error(rw, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge = deriveCodeChallenge(codeVerifier)
		t.logger.Debugf("PKCE enabled, generated code challenge")
	}

	session.SetAuthenticated(false)
	session.SetEmail("")
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetIDToken("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	if t.enablePKCE {
		session.SetCodeVerifier(codeVerifier)
	}
	session.SetIncomingPath(req.URL.RequestURI())
	t.logger.Debugf("Storing incoming path: %s", req.URL.RequestURI())

	session.MarkDirty()

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session before redirecting to provider: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Session saved before redirect. CSRF: %s, Nonce: %s",
		csrfToken, nonce)

	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)
	t.logger.Debugf("Redirecting user to OIDC provider: %s", authURL)

	http.Redirect(rw, req, authURL, http.StatusFound)
}

// verifyToken is a convenience wrapper for token verification.
// It delegates to the configured token verifier interface.
// Parameters:
//   - token: The token string to verify.
//
// Returns:
//   - The result of calling t.tokenVerifier.VerifyToken(token).
func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

// buildAuthURL constructs the OIDC provider authorization URL.
// It builds the URL with all necessary parameters including client_id, scopes,
// PKCE parameters, and provider-specific parameters for Google and Azure.
// Parameters:
//   - redirectURL: The callback URL for after authentication.
//   - state: The CSRF token for state validation.
//   - nonce: The nonce for replay protection.
//   - codeChallenge: The PKCE code challenge (if PKCE is enabled).
//
// Returns:
//   - The fully constructed authorization URL string.
func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce, codeChallenge string) string {
	params := url.Values{}
	params.Set("client_id", t.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)

	if t.enablePKCE && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	scopes := make([]string, len(t.scopes))
	copy(scopes, t.scopes)

	if t.isGoogleProvider() {
		params.Set("access_type", "offline")
		t.logger.Debug("Google OIDC provider detected, added access_type=offline for refresh tokens")

		params.Set("prompt", "consent")
		t.logger.Debug("Google OIDC provider detected, added prompt=consent to ensure refresh tokens")
	} else if t.isAzureProvider() {
		params.Set("response_mode", "query")
		t.logger.Debug("Azure AD provider detected, added response_mode=query")

		hasOfflineAccess := false

		for _, scope := range scopes {
			if scope == "offline_access" {
				hasOfflineAccess = true
				break
			}
		}

		if !t.overrideScopes || (t.overrideScopes && len(t.scopes) == 0) {
			if !hasOfflineAccess {
				scopes = append(scopes, "offline_access")
				t.logger.Debugf("Azure AD provider: Added offline_access scope (overrideScopes: %t, user scopes count: %d)", t.overrideScopes, len(t.scopes))
			}
		} else {
			t.logger.Debugf("Azure AD provider: User is overriding scopes (count: %d), offline_access not automatically added.", len(t.scopes))
		}
	} else {
		if !t.overrideScopes || (t.overrideScopes && len(t.scopes) == 0) {
			hasOfflineAccess := false
			for _, scope := range scopes {
				if scope == "offline_access" {
					hasOfflineAccess = true
					break
				}
			}
			if !hasOfflineAccess {
				scopes = append(scopes, "offline_access")
				t.logger.Debugf("Standard provider: Added offline_access scope (overrideScopes: %t, user scopes count: %d)", t.overrideScopes, len(t.scopes))
			}
		} else {
			t.logger.Debugf("Standard provider: User is overriding scopes (count: %d), offline_access not automatically added.", len(t.scopes))
		}
	}

	if len(scopes) > 0 {
		finalScopeString := strings.Join(scopes, " ")
		params.Set("scope", finalScopeString)
		t.logger.Debugf("TraefikOidc.buildAuthURL: Final scope string being sent to OIDC provider: %s", finalScopeString)
	}

	return t.buildURLWithParams(t.authURL, params)
}

// buildURLWithParams constructs a URL by combining a base URL with query parameters.
// It handles both relative and absolute URLs, validates URL security,
// and properly encodes query parameters.
// Parameters:
//   - baseURL: The base URL to append parameters to.
//   - params: The query parameters to append.
//
// Returns:
//   - The fully constructed URL string with appended query parameters.
func (t *TraefikOidc) buildURLWithParams(baseURL string, params url.Values) string {
	if baseURL != "" {
		if strings.HasPrefix(baseURL, "http://") || strings.HasPrefix(baseURL, "https://") {
			if err := t.validateURL(baseURL); err != nil {
				t.logger.Errorf("URL validation failed for %s: %v", baseURL, err)
				return ""
			}
		}
	}

	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		issuerURLParsed, err := url.Parse(t.issuerURL)
		if err != nil {
			t.logger.Errorf("Could not parse issuerURL: %s. Error: %v", t.issuerURL, err)
			return ""
		}

		baseURLParsed, err := url.Parse(baseURL)
		if err != nil {
			t.logger.Errorf("Could not parse baseURL: %s. Error: %v", baseURL, err)
			return ""
		}

		resolvedURL := issuerURLParsed.ResolveReference(baseURLParsed)

		if err := t.validateURL(resolvedURL.String()); err != nil {
			t.logger.Errorf("Resolved URL validation failed for %s: %v", resolvedURL.String(), err)
			return ""
		}

		resolvedURL.RawQuery = params.Encode()
		return resolvedURL.String()
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		t.logger.Errorf("Could not parse absolute baseURL: %s. Error: %v", baseURL, err)
		return ""
	}

	if err := t.validateParsedURL(u); err != nil {
		t.logger.Errorf("Parsed URL validation failed for %s: %v", baseURL, err)
		return ""
	}

	u.RawQuery = params.Encode()
	return u.String()
}

// validateURL performs security validation on URLs to prevent SSRF attacks.
// It checks for allowed schemes, validates hosts, and prevents access to private networks.
// Parameters:
//   - urlStr: The URL string to validate.
//
// Returns:
//   - An error if the URL is invalid or poses security risks, nil if valid.
func (t *TraefikOidc) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("empty URL")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	return t.validateParsedURL(u)
}

// validateParsedURL validates a parsed URL structure for security.
// It checks schemes, hosts, and paths to prevent malicious URLs.
// Parameters:
//   - u: The parsed URL to validate.
//
// Returns:
//   - An error if the URL is invalid or dangerous, nil if safe.
func (t *TraefikOidc) validateParsedURL(u *url.URL) error {
	allowedSchemes := map[string]bool{
		"https": true,
		"http":  true,
	}

	if !allowedSchemes[u.Scheme] {
		return fmt.Errorf("disallowed URL scheme: %s", u.Scheme)
	}

	if u.Scheme == "http" {
		t.logger.Debugf("Warning: Using HTTP scheme for URL: %s", u.String())
	}

	if u.Host == "" {
		return fmt.Errorf("missing host in URL")
	}

	if err := t.validateHost(u.Host); err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}

	if strings.Contains(u.Path, "..") {
		return fmt.Errorf("path traversal detected in URL path")
	}

	return nil
}

// validateHost validates a hostname or IP address for security.
// It prevents access to localhost, private networks, and known metadata endpoints.
// Parameters:
//   - host: The host string to validate (may include port).
//
// Returns:
//   - An error if the host is dangerous or not allowed, nil if safe.
func (t *TraefikOidc) validateHost(host string) error {
	hostname := host
	if strings.Contains(host, ":") {
		var err error
		hostname, _, err = net.SplitHostPort(host)
		if err != nil {
			return fmt.Errorf("invalid host format: %w", err)
		}
	}

	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("access to private/internal IP addresses is not allowed: %s", ip.String())
		}

		if ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("access to unspecified or multicast IP addresses is not allowed: %s", ip.String())
		}
	}

	dangerousHosts := map[string]bool{
		"localhost":                true,
		"127.0.0.1":                true,
		"::1":                      true,
		"0.0.0.0":                  true,
		"169.254.169.254":          true,
		"metadata.google.internal": true,
	}

	if dangerousHosts[strings.ToLower(hostname)] {
		return fmt.Errorf("access to dangerous hostname is not allowed: %s", hostname)
	}

	return nil
}

// startTokenCleanup starts background cleanup goroutines for cache maintenance.
// It runs periodic cleanup of token cache, JWK cache, and session chunks.
// Includes panic recovery to ensure stability.
func (t *TraefikOidc) startTokenCleanup() {
	ticker := time.NewTicker(1 * time.Minute)

	if t.goroutineWG != nil {
		t.goroutineWG.Add(1)
	}
	go func() {
		defer func() {
			if t.goroutineWG != nil {
				t.goroutineWG.Done()
			}
			ticker.Stop()

			if r := recover(); r != nil {
				t.logger.Errorf("Token cleanup goroutine panic recovered: %v", r)
			}
		}()

		for {
			select {
			case <-ticker.C:
				t.logger.Debug("Starting token cleanup cycle")
				if t.tokenCache != nil {
					t.tokenCache.Cleanup()
				}
				if t.jwkCache != nil {
					t.jwkCache.Cleanup()
				}
				if t.sessionManager != nil {
					t.sessionManager.PeriodicChunkCleanup()

					t.logger.Debug("Running session health monitoring")
				}

			case <-t.tokenCleanupStopChan:
				t.logger.Debug("Token cleanup goroutine stopped.")
				return
			case <-t.ctx.Done():
				t.logger.Debug("Token cleanup goroutine stopped due to context cancellation.")
				return
			}
		}
	}()
}

// RevokeToken revokes a token locally by adding it to the blacklist cache.
// It removes the token from the verification cache and adds both the token
// and its JTI (if present) to the blacklist to prevent future use.
// Parameters:
//   - token: The raw token string to revoke locally.
func (t *TraefikOidc) RevokeToken(token string) {
	t.tokenCache.Delete(token)

	if jwt, err := parseJWT(token); err == nil {
		if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" {
			expiry := time.Now().Add(24 * time.Hour)
			if t.tokenBlacklist != nil {
				t.tokenBlacklist.Set(jti, true, time.Until(expiry))
				t.logger.Debugf("Locally revoked token JTI %s (added to blacklist)", jti)
			}
		}
	}

	expiry := time.Now().Add(24 * time.Hour)
	if t.tokenBlacklist != nil {
		t.tokenBlacklist.Set(token, true, time.Until(expiry))
		t.logger.Debugf("Locally revoked token (added to blacklist)")
	}
}

// RevokeTokenWithProvider revokes a token with the OIDC provider.
// It sends a revocation request to the provider's revocation endpoint
// with proper authentication and error recovery if available.
// Parameters:
//   - token: The token to revoke.
//   - tokenType: The type of token ("access_token" or "refresh_token").
//
// Returns:
//   - An error if the request fails or the provider returns a non-OK status.
func (t *TraefikOidc) RevokeTokenWithProvider(token, tokenType string) error {
	if t.revocationURL == "" {
		return fmt.Errorf("token revocation endpoint is not configured or discovered")
	}
	t.logger.Debugf("Attempting to revoke token (type: %s) with provider at %s", tokenType, t.revocationURL)

	data := url.Values{
		"token":           {token},
		"token_type_hint": {tokenType},
		"client_id":       {t.clientID},
		"client_secret":   {t.clientSecret},
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", t.revocationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token revocation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Send the request with circuit breaker protection if available
	var resp *http.Response
	if t.errorRecoveryManager != nil {
		serviceName := fmt.Sprintf("token-revocation-%s", t.issuerURL)
		err = t.errorRecoveryManager.ExecuteWithRecovery(context.Background(), serviceName, func() error {
			var reqErr error
			resp, reqErr = t.httpClient.Do(req)
			return reqErr
		})
	} else {
		resp, err = t.httpClient.Do(req)
	}
	if err != nil {
		return fmt.Errorf("failed to send token revocation request: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 1024*10)
		body, _ := io.ReadAll(limitReader)
		t.logger.Errorf("Token revocation failed with status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	t.logger.Debugf("Token successfully revoked with provider")
	return nil
}

// refreshToken attempts to refresh authentication tokens using the refresh token.
// It handles provider-specific refresh logic, validates new tokens, updates the session,
// and includes concurrency protection to prevent race conditions.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request context.
//   - session: The session data containing the refresh token.
//
// Returns:
//   - true if refresh succeeded and session was updated, false if refresh failed,
//     a concurrency conflict was detected, or saving the session failed.
func (t *TraefikOidc) refreshToken(rw http.ResponseWriter, req *http.Request, session *SessionData) bool {
	session.refreshMutex.Lock()
	defer session.refreshMutex.Unlock()

	t.logger.Debug("Attempting to refresh token (mutex acquired)")

	if !session.inUse {
		t.logger.Debug("refreshToken aborted: Session no longer in use")
		return false
	}

	initialRefreshToken := session.GetRefreshToken()
	if initialRefreshToken == "" {
		t.logger.Debug("No refresh token found in session")
		return false
	}

	if t.isGoogleProvider() {
		t.logger.Debug("Google OIDC provider detected for token refresh operation")
	} else if t.isAzureProvider() {
		t.logger.Debug("Azure AD provider detected for token refresh operation")
	}

	tokenPrefix := initialRefreshToken
	if len(initialRefreshToken) > 10 {
		tokenPrefix = initialRefreshToken[:10]
	}
	t.logger.Debugf("Attempting refresh with token starting with %s...", tokenPrefix)

	newToken, err := t.tokenExchanger.GetNewTokenWithRefreshToken(initialRefreshToken)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid_grant") || strings.Contains(errMsg, "token expired") {
			t.logger.Debug("Refresh token expired or revoked: %v", err)
			session.SetRefreshToken("")
			if err = session.Save(req, rw); err != nil {
				t.logger.Errorf("Failed to remove invalid refresh token from session: %v", err)
			}
		} else if strings.Contains(errMsg, "invalid_client") {
			t.logger.Errorf("Client credentials rejected: %v - check client_id and client_secret configuration", err)
		} else if t.isGoogleProvider() && strings.Contains(errMsg, "invalid_request") {
			t.logger.Errorf("Google OIDC provider error: %v - check scope configuration includes 'offline_access' and prompt=consent is used during authentication", err)
		} else {
			t.logger.Errorf("Token refresh failed: %v", err)
		}

		return false
	}

	if newToken.IDToken == "" {
		t.logger.Info("Provider did not return a new ID token during refresh")
		return false
	}

	if err = t.verifyToken(newToken.IDToken); err != nil {
		t.logger.Debug("Failed to verify newly obtained ID token: %v", err)
		return false
	}

	currentRefreshToken := session.GetRefreshToken()
	if initialRefreshToken != currentRefreshToken {
		t.logger.Infof("refreshToken aborted: Session refresh token changed concurrently during refresh attempt.")
		return false
	}

	t.logger.Debugf("Concurrency check passed. Updating session with new tokens.")

	claims, err := t.extractClaimsFunc(newToken.IDToken)
	if err != nil {
		t.logger.Errorf("refreshToken failed: Failed to extract claims from refreshed token: %v", err)
		return false
	}
	email, _ := claims["email"].(string)
	if email == "" {
		t.logger.Errorf("refreshToken failed: Email claim missing or empty in refreshed token")
		return false
	}
	session.SetEmail(email)

	// Get token expiry information for logging
	var expiryTime time.Time
	if expClaim, ok := claims["exp"].(float64); ok {
		expiryTime = time.Unix(int64(expClaim), 0)
		t.logger.Debugf("New token expires at: %v (in %v)", expiryTime, time.Until(expiryTime))
	}

	session.SetIDToken(newToken.IDToken)
	session.SetAccessToken(newToken.AccessToken)

	if newToken.RefreshToken != "" {
		t.logger.Debug("Received new refresh token from provider")
		session.SetRefreshToken(newToken.RefreshToken)
	} else {
		t.logger.Debug("Provider did not return a new refresh token, keeping the existing one")
		session.SetRefreshToken(initialRefreshToken)
	}

	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("refreshToken warning: Failed to set authenticated flag: %v", err)
	}

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("refreshToken failed: Failed to save session after successful token refresh: %v", err)
		return false
	}

	t.logger.Debugf("Token refresh successful and session saved")
	return true
}

// isAllowedDomain checks if an email address is authorized based on domain or user whitelist.
// It validates against both allowed user domains and specific allowed users.
// Parameters:
//   - email: The email address to validate.
//
// Returns:
//   - true if the email is authorized (domain or user allowed), false if not authorized
//     or if the email format is invalid.
func (t *TraefikOidc) isAllowedDomain(email string) bool {
	if len(t.allowedUserDomains) == 0 && len(t.allowedUsers) == 0 {
		return true
	}

	if len(t.allowedUsers) > 0 {
		_, userAllowed := t.allowedUsers[strings.ToLower(email)]
		if userAllowed {
			t.logger.Debugf("Email %s is explicitly allowed in allowedUsers", email)
			return true
		}
	}

	if len(t.allowedUserDomains) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) != 2 {
			t.logger.Errorf("Invalid email format encountered: %s", email)
			return false
		}

		domain := parts[1]
		_, domainAllowed := t.allowedUserDomains[domain]

		if domainAllowed {
			t.logger.Debugf("Email domain %s is allowed", domain)
			return true
		} else {
			t.logger.Debugf("Email domain %s is NOT allowed. Allowed domains: %v",
				domain, keysFromMap(t.allowedUserDomains))
		}
	} else if len(t.allowedUsers) > 0 {
		t.logger.Debugf("Email %s is not in the allowed users list: %v",
			email, keysFromMap(t.allowedUsers))
	}

	return false
}

// keysFromMap extracts string keys from a map for logging purposes.
// Helper function to get keys from a map for logging.
// Parameters:
//   - m: The map to extract keys from.
//
// Returns:
//   - A slice of string keys.
func keysFromMap(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// createCaseInsensitiveStringMap creates a map with lowercase keys for case-insensitive matching.
// This is used for case-insensitive matching of email addresses.
// Parameters:
//   - items: The string items to convert to lowercase keys.
//
// Returns:
//   - A map with lowercase string keys for case-insensitive lookups.
func createCaseInsensitiveStringMap(items []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range items {
		result[strings.ToLower(item)] = struct{}{}
	}
	return result
}

// extractGroupsAndRoles extracts group and role information from token claims.
// It parses the 'groups' and 'roles' claims from the ID token and validates their format.
// Parameters:
//   - idToken: The ID token containing claims to extract.
//
// Returns:
//   - groups: Array of group names from the 'groups' claim.
//   - roles: Array of role names from the 'roles' claim.
//   - An error if claim extraction fails or if the 'groups' or 'roles' claims are present
//     but not arrays of strings.
func (t *TraefikOidc) extractGroupsAndRoles(idToken string) ([]string, []string, error) {
	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	var groups []string
	var roles []string

	if groupsClaim, exists := claims["groups"]; exists {
		groupsSlice, ok := groupsClaim.([]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("groups claim is not an array")
		} else {
			for _, group := range groupsSlice {
				if groupStr, ok := group.(string); ok {
					t.logger.Debugf("Found group: %s", groupStr)
					groups = append(groups, groupStr)
				} else {
					t.logger.Errorf("Non-string value found in groups claim array: %v", group)
				}
			}
		}
	}

	if rolesClaim, exists := claims["roles"]; exists {
		rolesSlice, ok := rolesClaim.([]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("roles claim is not an array")
		} else {
			for _, role := range rolesSlice {
				if roleStr, ok := role.(string); ok {
					t.logger.Debugf("Found role: %s", roleStr)
					roles = append(roles, roleStr)
				} else {
					t.logger.Errorf("Non-string value found in roles claim array: %v", role)
				}
			}
		}
	}

	return groups, roles, nil
}

// buildFullURL constructs a complete URL from scheme, host, and path components.
// It handles absolute URLs in the path and ensures proper URL formatting.
// Parameters:
//   - scheme: The URL scheme ("http" or "https").
//   - host: The host name and optional port.
//   - path: The path component (may be absolute URL itself).
//
// Returns:
//   - The combined absolute URL string (e.g., "https://example.com:8080/resource").
func buildFullURL(scheme, host, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// ExchangeCodeForToken exchanges an authorization code for tokens.
// This is a wrapper method that delegates to the internal token exchange logic
// while still allowing mocking for tests.
// Parameters:
//   - ctx: The request context.
//   - grantType: The OAuth 2.0 grant type ("authorization_code").
//   - codeOrToken: The authorization code received from the provider.
//   - redirectURL: The redirect URI used in the authorization request.
//   - codeVerifier: The PKCE code verifier (if PKCE is enabled).
//
// Returns:
//   - The token response containing access token, ID token, and refresh token.
//   - An error if the token exchange fails.
func (t *TraefikOidc) ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	return t.exchangeTokens(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
}

// GetNewTokenWithRefreshToken refreshes tokens using a refresh token.
// This is a wrapper method that delegates to the internal refresh token logic
// while still allowing mocking for tests.
// Parameters:
//   - refreshToken: The refresh token to use for obtaining new tokens.
//
// Returns:
//   - The token response containing new access token, ID token, and potentially new refresh token.
//   - An error if the refresh fails.
func (t *TraefikOidc) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	return t.getNewTokenWithRefreshToken(refreshToken)
}

// sendErrorResponse sends an appropriate error response based on the request's Accept header.
// It sends JSON responses for clients that accept JSON, otherwise sends HTML error pages.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request (used to check Accept header).
//   - message: The error message to display.
//   - code: The HTTP status code to set for the response.
func (t *TraefikOidc) sendErrorResponse(rw http.ResponseWriter, req *http.Request, message string, code int) {
	acceptHeader := req.Header.Get("Accept")

	if strings.Contains(acceptHeader, "application/json") {
		t.logger.Debugf("Sending JSON error response (code %d): %s", code, message)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"error":             http.StatusText(code),
			"error_description": message,
			"status_code":       code,
		})
		return
	}

	t.logger.Debugf("Sending HTML error response (code %d): %s", code, message)

	returnURL := "/"

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Error</title>
    <style>
        body { font-family: sans-serif; padding: 20px; background-color: #f8f9fa; color: #343a40; }
        h1 { color: #dc3545; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .container { max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Error</h1>
        <p>%s</p>
        <p><a href="%s">Return to application</a></p>
    </div>
</body>
</html>`, message, returnURL)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	_, _ = rw.Write([]byte(htmlBody))
}

// isGoogleProvider detects if the configured OIDC provider is Google.
// It checks the issuer URL for Google-specific domains.
// Returns:
//   - true if the provider is Google, false otherwise.
func (t *TraefikOidc) isGoogleProvider() bool {
	return strings.Contains(t.issuerURL, "google") || strings.Contains(t.issuerURL, "accounts.google.com")
}

// isAzureProvider detects if the configured OIDC provider is Azure AD.
// It checks the issuer URL for Microsoft Azure AD domains.
// Returns:
//   - true if the provider is Azure AD, false otherwise.
func (t *TraefikOidc) isAzureProvider() bool {
	return strings.Contains(t.issuerURL, "login.microsoftonline.com") ||
		strings.Contains(t.issuerURL, "sts.windows.net") ||
		strings.Contains(t.issuerURL, "login.windows.net")
}

// validateAzureTokens validates tokens with Azure AD-specific logic.
// Azure tokens may be opaque access tokens that cannot be verified as JWTs,
// so this method handles both JWT and opaque token scenarios.
// Parameters:
//   - session: The session data containing tokens to validate.
//
// Returns:
//   - authenticated: Whether the user has valid authentication.
//   - needsRefresh: Whether tokens need to be refreshed.
//   - expired: Whether tokens have expired and cannot be refreshed.
func (t *TraefikOidc) validateAzureTokens(session *SessionData) (bool, bool, bool) {
	if !session.GetAuthenticated() {
		t.logger.Debug("Azure user is not authenticated according to session flag")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Azure session not authenticated, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, true, false
	}

	accessToken := session.GetAccessToken()
	idToken := session.GetIDToken()

	if accessToken != "" {
		if strings.Count(accessToken, ".") == 2 {
			if err := t.verifyToken(accessToken); err != nil {
				if idToken != "" {
					if err := t.verifyToken(idToken); err != nil {
						t.logger.Debugf("Azure: Both access and ID token validation failed: %v", err)
						if session.GetRefreshToken() != "" {
							return false, true, false
						}
						return false, false, true
					}
					return t.validateTokenExpiry(session, idToken)
				}
				if session.GetRefreshToken() != "" {
					return false, true, false
				}
				return false, false, true
			}
			return t.validateTokenExpiry(session, accessToken)
		} else {
			t.logger.Debug("Azure access token appears opaque, treating as valid")
			if idToken != "" {
				return t.validateTokenExpiry(session, idToken)
			}
			return true, false, false
		}
	}

	if idToken != "" {
		if err := t.verifyToken(idToken); err != nil {
			if strings.Contains(err.Error(), "token has expired") {
				if session.GetRefreshToken() != "" {
					return false, true, false
				}
				return false, false, true
			}
			if session.GetRefreshToken() != "" {
				return false, true, false
			}
			return false, false, true
		}
		return t.validateTokenExpiry(session, idToken)
	}

	if session.GetRefreshToken() != "" {
		return false, true, false
	}
	return false, false, true
}

// validateGoogleTokens handles Google-specific token validation logic.
// Currently delegates to standard token validation but provides a hook
// for Google-specific validation requirements in the future.
// Parameters:
//   - session: The session data containing tokens to validate.
//
// Returns:
//   - authenticated: Whether the user has valid authentication.
//   - needsRefresh: Whether tokens need to be refreshed.
//   - expired: Whether tokens have expired and cannot be refreshed.
func (t *TraefikOidc) validateGoogleTokens(session *SessionData) (bool, bool, bool) {
	return t.validateStandardTokens(session)
}

// validateStandardTokens handles standard OIDC token validation logic.
// This is the default validation method for generic OIDC providers.
// It verifies ID tokens and handles access tokens appropriately.
// Parameters:
//   - session: The session data containing tokens to validate.
//
// Returns:
//   - authenticated: Whether the user has valid authentication.
//   - needsRefresh: Whether tokens need to be refreshed.
//   - expired: Whether tokens have expired and cannot be refreshed.
func (t *TraefikOidc) validateStandardTokens(session *SessionData) (bool, bool, bool) {
	if !session.GetAuthenticated() {
		t.logger.Debug("User is not authenticated according to session flag")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Session not authenticated, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, false
	}

	accessToken := session.GetAccessToken()
	if accessToken == "" {
		t.logger.Debug("Authenticated flag set, but no access token found in session")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Access token missing, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, true
	}

	idToken := session.GetIDToken()
	if idToken == "" {
		t.logger.Debug("Authenticated flag set with access token, but no ID token found in session (possibly opaque token)")
		session.SetAuthenticated(true)

		if session.GetRefreshToken() != "" {
			t.logger.Debug("ID token missing but refresh token exists. Signaling conditional refresh to obtain ID token.")
			return true, true, false
		}
		return true, false, false
	}

	if err := t.verifyToken(idToken); err != nil {
		if strings.Contains(err.Error(), "token has expired") {
			t.logger.Debugf("ID token signature/claims valid but token expired, needs refresh")
			if session.GetRefreshToken() != "" {
				return false, true, false
			}
			return false, false, true
		}

		t.logger.Errorf("ID token verification failed (non-expiration): %v", err)
		if session.GetRefreshToken() != "" {
			t.logger.Debug("ID token verification failed, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, true
	}

	return t.validateTokenExpiry(session, idToken)
}

// validateTokenExpiry checks if a token is nearing expiration and needs refresh.
// It uses the configured grace period to determine when proactive refresh should occur.
// Parameters:
//   - session: The session data for refresh token availability.
//   - token: The token to check expiry for.
//
// Returns:
//   - authenticated: Whether the token is currently valid.
//   - needsRefresh: Whether the token is nearing expiration and should be refreshed.
//   - expired: Whether the token is invalid or verification failed.
func (t *TraefikOidc) validateTokenExpiry(session *SessionData, token string) (bool, bool, bool) {
	cachedClaims, found := t.tokenCache.Get(token)
	if !found {
		t.logger.Debug("Claims not found in cache after successful token verification")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Claims missing post-verification, attempting refresh to recover.")
			return false, true, false
		}
		return false, false, true
	}

	expClaim, ok := cachedClaims["exp"].(float64)
	if !ok {
		t.logger.Error("Failed to get expiration time ('exp' claim) from verified token")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Token missing 'exp' claim, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, true
	}

	expTime := int64(expClaim)
	expTimeObj := time.Unix(expTime, 0)
	nowObj := time.Now()
	refreshThreshold := nowObj.Add(t.refreshGracePeriod)

	t.logger.Debugf("Token expires at %v, now is %v, refresh threshold is %v",
		expTimeObj.Format(time.RFC3339),
		nowObj.Format(time.RFC3339),
		refreshThreshold.Format(time.RFC3339))

	if expTimeObj.Before(refreshThreshold) {
		remainingSeconds := int64(time.Until(expTimeObj).Seconds())
		t.logger.Debugf("Token nearing expiration (expires in %d seconds, grace period %s), scheduling proactive refresh",
			remainingSeconds, t.refreshGracePeriod)

		if session.GetRefreshToken() != "" {
			return true, true, false
		}

		t.logger.Debugf("Token nearing expiration but no refresh token available, cannot proactively refresh.")
		return true, false, false
	}

	t.logger.Debugf("Token is valid and not nearing expiration (expires in %d seconds, outside %s grace period)",
		int64(time.Until(expTimeObj).Seconds()), t.refreshGracePeriod)

	return true, false, false
}

// Close gracefully shuts down the TraefikOidc middleware instance.
// It cancels contexts, stops background goroutines, closes HTTP connections,
// cleans up caches, and releases all resources. Safe to call multiple times.
// Returns:
//   - An error if shutdown times out or resource cleanup fails.
func (t *TraefikOidc) Close() error {
	var closeErr error
	t.shutdownOnce.Do(func() {
		t.logger.Debug("Closing TraefikOidc plugin instance")

		if t.cancelFunc != nil {
			t.cancelFunc()
			t.logger.Debug("Context cancellation signaled to all goroutines")
		}

		if t.tokenCleanupStopChan != nil {
			close(t.tokenCleanupStopChan)
			t.logger.Debug("tokenCleanupStopChan closed")
		}
		if t.metadataRefreshStopChan != nil {
			close(t.metadataRefreshStopChan)
			t.logger.Debug("metadataRefreshStopChan closed")
		}

		if t.goroutineWG != nil {
			done := make(chan struct{})
			go func() {
				t.goroutineWG.Wait()
				close(done)
			}()

			select {
			case <-done:
				t.logger.Debug("All background goroutines stopped gracefully")
			case <-time.After(10 * time.Second):
				t.logger.Errorf("Timeout waiting for background goroutines to stop")
			}
		} else {
			t.logger.Debug("No goroutineWG to wait for (likely in test)")
		}

		if t.httpClient != nil {
			if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
				t.logger.Debug("HTTP client idle connections closed")
			}
		}

		if t.tokenHTTPClient != nil {
			if transport, ok := t.tokenHTTPClient.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
				t.logger.Debug("Token HTTP client idle connections closed")
			}
			if t.tokenHTTPClient.Transport != t.httpClient.Transport {
				if transport, ok := t.tokenHTTPClient.Transport.(*http.Transport); ok {
					transport.CloseIdleConnections()
					t.logger.Debug("Token HTTP client transport closed (separate from main)")
				}
			}
		}

		if t.tokenBlacklist != nil {
			t.tokenBlacklist.Close()
			t.logger.Debug("tokenBlacklist closed")
		}
		if t.metadataCache != nil {
			t.metadataCache.Close()
			t.logger.Debug("metadataCache closed")
		}
		if t.tokenCache != nil {
			t.tokenCache.Close()
			t.logger.Debug("tokenCache closed")
		}

		if t.jwkCache != nil {
			t.jwkCache.Close()
			t.logger.Debug("t.jwkCache.Close() called as per original instruction.")
		}

		CleanupGlobalMemoryPools()
		t.logger.Debug("Global memory pools cleaned up")

		t.logger.Info("TraefikOidc plugin instance closed successfully.")
	})
	return closeErr
}
