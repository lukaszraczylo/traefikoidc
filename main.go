// Package traefikoidc provides OIDC authentication middleware for Traefik.
// It supports multiple OIDC providers including Google, Azure AD, and generic OIDC providers
// with features like token refresh, session management, and provider-specific optimizations.
package traefikoidc

import (
	"context"
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

// NOTE: VerifyToken method moved to token_manager.go

// NOTE: cacheVerifiedToken method moved to token_manager.go

// NOTE: VerifyJWTSignatureAndClaims method moved to token_manager.go

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
	cacheManager := GetGlobalCacheManager(goroutineWG)

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
		securityHeadersApplier:  config.GetSecurityHeadersApplier(),
	}

	t.sessionManager, _ = NewSessionManager(config.SessionEncryptionKey, config.ForceHTTPS, config.CookieDomain, t.logger)
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

	// Setup cleanup hook for when context is cancelled
	if pluginCtx != nil {
		go func() {
			<-pluginCtx.Done()
			t.Close()
		}()
	}

	return t, nil
}

// ============================================================================
// PROVIDER METADATA MANAGEMENT
// ============================================================================

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
	// Use singleton resource manager for metadata refresh
	rm := GetResourceManager()
	taskName := "singleton-metadata-refresh"

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
		rm.StartBackgroundTask(taskName)
		t.logger.Debug("Started singleton metadata refresh task")
	} else {
		t.logger.Debug("Metadata refresh task already running, skipping duplicate")
	}
}

// NOTE: ServeHTTP method moved to middleware.go

// NOTE: processAuthorizedRequest method moved to middleware.go

// NOTE: handleExpiredToken method moved to auth_flow.go

// NOTE: handleCallback method moved to auth_flow.go

// NOTE: determineExcludedURL method moved to url_helpers.go

// NOTE: determineScheme method moved to url_helpers.go

// NOTE: determineHost method moved to url_helpers.go

// NOTE: isUserAuthenticated method moved to auth_flow.go

// NOTE: defaultInitiateAuthentication method moved to auth_flow.go

// NOTE: verifyToken method moved to token_manager.go

// NOTE: safeLog methods moved to utilities.go

// NOTE: buildAuthURL method moved to url_helpers.go

// NOTE: buildURLWithParams method moved to url_helpers.go

// NOTE: validateURL method moved to url_helpers.go

// NOTE: validateParsedURL method moved to url_helpers.go

// NOTE: validateHost method moved to url_helpers.go

// NOTE: startTokenCleanup method moved to token_manager.go

// NOTE: RevokeToken method moved to token_manager.go

// NOTE: RevokeTokenWithProvider method moved to token_manager.go

// NOTE: refreshToken method moved to token_manager.go

// NOTE: isAllowedDomain method moved to utilities.go

// NOTE: keysFromMap function moved to utilities.go

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

// NOTE: extractGroupsAndRoles method moved to token_manager.go

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

// NOTE: ExchangeCodeForToken method moved to token_manager.go

// NOTE: GetNewTokenWithRefreshToken method moved to token_manager.go

// NOTE: sendErrorResponse method moved to utilities.go

// NOTE: isGoogleProvider method moved to token_manager.go

// NOTE: isAzureProvider method moved to token_manager.go

// NOTE: validateAzureTokens method moved to token_manager.go

// NOTE: validateGoogleTokens method moved to token_manager.go

// NOTE: validateStandardTokens method moved to token_manager.go

// NOTE: validateTokenExpiry method moved to token_manager.go

// NOTE: Close method moved to utilities.go

// NOTE: isAjaxRequest method moved to auth_flow.go

// NOTE: isRefreshTokenExpired method moved to auth_flow.go
