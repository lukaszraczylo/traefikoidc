// Package traefikoidc provides OIDC authentication middleware for Traefik.
// It supports multiple OIDC providers including Google, Azure AD, and generic OIDC providers
// with features like token refresh, session management, and provider-specific optimizations.
package traefikoidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

const (
	ConstSessionTimeout = 86400
)

// isTestMode detects if the code is running in a test environment.
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

	return false
}

// mergeScopes combines default scopes with user-provided scopes, removing duplicates.
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

// defaultExcludedURLs are the paths that are excluded from authentication
var defaultExcludedURLs = map[string]struct{}{
	"/favicon": {},
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
	return NewWithContext(ctx, config, next, name)
}

// NewWithContext creates a new TraefikOidc middleware instance with proper context handling.
// This is the preferred constructor that ensures proper goroutine lifecycle management.
func NewWithContext(ctx context.Context, config *Config, next http.Handler, name string) (*TraefikOidc, error) {
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
	cacheManager := GetGlobalCacheManagerWithConfig(goroutineWG, config)

	// Use provided context instead of creating new one
	var pluginCtx context.Context
	var cancelFunc context.CancelFunc
	if ctx != nil {
		pluginCtx, cancelFunc = context.WithCancel(ctx)
	} else {
		pluginCtx, cancelFunc = context.WithCancel(context.Background())
	}

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
		tokenBlacklist:     cacheManager.GetSharedTokenBlacklist(),
		tokenTypeCache:     cacheManager.GetSharedTokenTypeCache(), // Cache for token type detection
		jwkCache:           cacheManager.GetSharedJWKCache(),
		metadataCache:      cacheManager.GetSharedMetadataCache(),
		introspectionCache: cacheManager.GetSharedIntrospectionCache(), // Cache for introspection results
		clientID:           config.ClientID,
		clientSecret:       config.ClientSecret,
		audience: func() string {
			if config.Audience != "" {
				return config.Audience
			}
			return config.ClientID
		}(),
		roleClaimName: func() string {
			if config.RoleClaimName != "" {
				return config.RoleClaimName
			}
			return "roles" // Backward compatible default
		}(),
		groupClaimName: func() string {
			if config.GroupClaimName != "" {
				return config.GroupClaimName
			}
			return "groups" // Backward compatible default
		}(),
		userIdentifierClaim: func() string {
			if config.UserIdentifierClaim != "" {
				return config.UserIdentifierClaim
			}
			return "email" // Backward compatible default
		}(),
		forceHTTPS:                config.ForceHTTPS,
		enablePKCE:                config.EnablePKCE,
		overrideScopes:            config.OverrideScopes,
		strictAudienceValidation:  config.StrictAudienceValidation,
		allowOpaqueTokens:         config.AllowOpaqueTokens,
		requireTokenIntrospection: config.RequireTokenIntrospection,
		disableReplayDetection:    config.DisableReplayDetection,
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
		securityHeadersApplier:  config.GetSecurityHeadersApplier(),
		scopeFilter:             NewScopeFilter(logger), // NEW - for discovery-based scope filtering
		dcrConfig:               config.DynamicClientRegistration,
		allowPrivateIPAddresses: config.AllowPrivateIPAddresses,
		minimalHeaders:          config.MinimalHeaders,
	}

	// Log audience configuration
	if config.Audience != "" && config.Audience != config.ClientID {
		t.logger.Infof("Custom audience configured: %s", config.Audience)
	} else {
		t.logger.Debugf("No custom audience specified, using clientID as audience: %s", t.clientID)
	}

	// Convert sessionMaxAge from seconds to duration (0 will use default 24 hours)
	sessionMaxAge := time.Duration(config.SessionMaxAge) * time.Second
	t.sessionManager, _ = NewSessionManager(config.SessionEncryptionKey, config.ForceHTTPS, config.CookieDomain, config.CookiePrefix, sessionMaxAge, t.logger) // Safe to ignore: session manager creation with fallback to defaults
	t.errorRecoveryManager = NewErrorRecoveryManager(t.logger)

	// Initialize token resilience manager with default configuration
	tokenResilienceConfig := DefaultTokenResilienceConfig()
	t.tokenResilienceManager = NewTokenResilienceManager(tokenResilienceConfig, t.logger)

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

	// Start memory monitoring for leak detection and performance insights
	memoryMonitor := GetGlobalMemoryMonitor()
	monitorInterval := 60 * time.Second
	if isTestMode() {
		monitorInterval = 100 * time.Millisecond // Fast interval for tests
	}
	memoryMonitor.StartMonitoring(pluginCtx, monitorInterval)
	logger.Debug("Started global memory monitoring")

	logger.Debugf("TraefikOidc.New: Final t.scopes initialized to: %v", t.scopes)

	t.providerURL = config.ProviderURL

	// Use singleton resource manager for metadata initialization
	rm := GetResourceManager()

	// Add reference for this instance
	rm.AddReference(name)

	// Initialize metadata in a goroutine with proper tracking
	if t.goroutineWG != nil {
		t.goroutineWG.Add(1)
	}
	go func() {
		defer func() {
			if t.goroutineWG != nil {
				t.goroutineWG.Done()
			}
			// Recover from panics to prevent goroutine leaks
			if r := recover(); r != nil {
				t.safeLogErrorf("Initialize metadata goroutine panic recovered: %v", r)
			}
		}()
		t.initializeMetadata(config.ProviderURL)
	}()

	// Setup cleanup hook for when context is canceled
	if pluginCtx != nil {
		go func() {
			<-pluginCtx.Done()
			_ = t.Close() // Safe to ignore: cleanup on context cancellation
		}()
	}

	return t, nil
}

// initializeMetadata initializes OIDC provider metadata by fetching configuration.
// It retrieves the provider's .well-known/openid-configuration and updates
// internal endpoint URLs. Uses error recovery if available for resilient fetching.
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
func (t *TraefikOidc) initializeMetadata(providerURL string) {
	t.safeLogDebug("Starting provider metadata discovery")

	// Ensure initComplete is always closed, even on failure
	defer func() {
		select {
		case <-t.initComplete:
			// Already closed, do nothing
		default:
			close(t.initComplete)
		}
	}()

	// Get metadata from cache or fetch it with error recovery if available
	var metadata *ProviderMetadata
	var err error
	if t.errorRecoveryManager != nil {
		metadata, err = t.metadataCache.GetMetadataWithRecovery(providerURL, t.httpClient, t.logger, t.errorRecoveryManager)
	} else {
		metadata, err = t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
	}
	if err != nil {
		t.safeLogErrorf("Failed to get provider metadata: %v", err)
		return
	}

	if metadata != nil {
		t.safeLogDebug("Successfully initialized provider metadata")
		t.updateMetadataEndpoints(metadata)
		return
	}

	t.safeLogError("Received nil metadata during initialization")
}

// updateMetadataEndpoints updates internal endpoint URLs with discovered metadata.
// It sets the authorization URL, token URL, JWKS URL, issuer URL, revocation URL,
// end session URL, introspection URL, and registration URL based on the provider's metadata.
// If Dynamic Client Registration is enabled and no ClientID is configured, it will
// automatically register the client with the provider.
// Parameters:
//   - metadata: A pointer to the ProviderMetadata struct containing the discovered endpoints.
func (t *TraefikOidc) updateMetadataEndpoints(metadata *ProviderMetadata) {
	t.metadataMu.Lock()

	t.jwksURL = metadata.JWKSURL
	t.scopesSupported = metadata.ScopesSupported // Store supported scopes from discovery
	t.authURL = metadata.AuthURL
	t.tokenURL = metadata.TokenURL
	t.issuerURL = metadata.Issuer
	t.revocationURL = metadata.RevokeURL
	t.endSessionURL = metadata.EndSessionURL
	t.introspectionURL = metadata.IntrospectionURL // OAuth 2.0 Token Introspection endpoint (RFC 7662)
	t.registrationURL = metadata.RegistrationURL   // OIDC Dynamic Client Registration endpoint (RFC 7591)

	t.metadataMu.Unlock()

	// Log introspection endpoint availability for opaque token support
	if t.introspectionURL != "" {
		t.logger.Debugf("Token introspection endpoint discovered: %s", t.introspectionURL)
		if t.allowOpaqueTokens {
			t.logger.Debugf("Opaque token support enabled with introspection endpoint")
		}
	} else if t.allowOpaqueTokens || t.requireTokenIntrospection {
		t.logger.Infof("⚠️  Opaque tokens enabled but no introspection endpoint available from provider")
	}

	// Log registration endpoint availability
	if t.registrationURL != "" {
		t.logger.Debugf("Dynamic client registration endpoint discovered: %s", t.registrationURL)
	}

	// Perform Dynamic Client Registration if enabled and ClientID is not set
	if t.dcrConfig != nil && t.dcrConfig.Enabled && t.clientID == "" {
		t.performDynamicClientRegistration()
	}
}

// performDynamicClientRegistration performs automatic client registration with the OIDC provider
func (t *TraefikOidc) performDynamicClientRegistration() {
	t.logger.Info("Dynamic Client Registration enabled - registering client with provider")

	// Initialize the DCR registrar if not already done
	if t.dynamicClientRegistrar == nil {
		t.dynamicClientRegistrar = NewDynamicClientRegistrar(
			t.httpClient,
			t.logger,
			t.dcrConfig,
			t.providerURL,
		)
	}

	// Get registration endpoint (from metadata or config override)
	registrationEndpoint := t.registrationURL
	if t.dcrConfig.RegistrationEndpoint != "" {
		registrationEndpoint = t.dcrConfig.RegistrationEndpoint
	}

	// Perform registration
	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()

	resp, err := t.dynamicClientRegistrar.RegisterClient(ctx, registrationEndpoint)
	if err != nil {
		t.logger.Errorf("Dynamic Client Registration failed: %v", err)
		return
	}

	// Update client credentials from registration response
	t.metadataMu.Lock()
	t.clientID = resp.ClientID
	t.clientSecret = resp.ClientSecret
	if t.audience == "" {
		t.audience = resp.ClientID // Default audience to client ID
	}
	t.metadataMu.Unlock()

	t.logger.Infof("Dynamic Client Registration successful - client_id: %s", resp.ClientID)

	// Log additional registration details
	if resp.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(resp.ClientSecretExpiresAt, 0)
		t.logger.Infof("Client secret expires at: %s", expiresAt.Format(time.RFC3339))
	}
	if resp.RegistrationClientURI != "" {
		t.logger.Debugf("Registration management URI: %s", resp.RegistrationClientURI)
	}
}

// startMetadataRefresh starts a background goroutine that periodically refreshes provider metadata.
// It runs every 2 hours and implements exponential backoff for consecutive failures.
// The refresh helps ensure endpoint URLs stay current and handles provider configuration changes.
// Parameters:
//   - providerURL: The base URL of the OIDC provider, used for subsequent refresh attempts.
func (t *TraefikOidc) startMetadataRefresh(providerURL string) {
	// Use singleton resource manager for metadata refresh
	rm := GetResourceManager()
	// Use last 6 chars of provider URL hash to create unique task name per realm
	// This fixes multi-realm support where different Keycloak realms need separate refresh tasks
	hash := sha256.Sum256([]byte(providerURL))
	taskName := "singleton-metadata-refresh-" + hex.EncodeToString(hash[:])[0:6]

	// Create refresh function
	refreshFunc := func() {
		if t.metadataCache == nil || t.httpClient == nil {
			return
		}

		metadata, err := t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
		if err != nil {
			t.safeLogErrorf("Failed to refresh provider metadata: %v", err)
			return
		}

		if metadata != nil {
			t.updateMetadataEndpoints(metadata)
			t.safeLogDebug("Successfully refreshed provider metadata")
		}
	}

	// Register as singleton task - will return existing if already registered
	err := rm.RegisterBackgroundTask(taskName, 2*time.Hour, refreshFunc)
	if err != nil {
		t.logger.Errorf("Failed to register metadata refresh task: %v", err)
		return
	}

	// Start the task if not already running
	if !rm.IsTaskRunning(taskName) {
		_ = rm.StartBackgroundTask(taskName) // Safe to ignore: task registration succeeded, start is best-effort
		t.logger.Debug("Started singleton metadata refresh task")
	} else {
		t.logger.Debug("Metadata refresh task already running, skipping duplicate")
	}
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
