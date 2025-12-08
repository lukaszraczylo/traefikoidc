// Package traefikoidc provides OIDC authentication middleware for Traefik.
package traefikoidc

import (
	"context"
	"net/http"
	"sync"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

// CacheInterface defines the common cache operations
type CacheInterface interface {
	Set(key string, value any, ttl time.Duration)
	Get(key string) (any, bool)
	Delete(key string)
	SetMaxSize(size int)
	Size() int
	Clear()
	Cleanup()
	Close()
	GetStats() map[string]any // For testing and monitoring
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

// ProviderMetadata represents OIDC provider configuration data.
// This data is typically retrieved from the provider's .well-known/openid-configuration endpoint
// and contains essential URLs for authentication, token exchange, and key retrieval.
type ProviderMetadata struct {
	Issuer           string   `json:"issuer"`
	AuthURL          string   `json:"authorization_endpoint"`
	TokenURL         string   `json:"token_endpoint"`
	JWKSURL          string   `json:"jwks_uri"`
	RevokeURL        string   `json:"revocation_endpoint"`
	EndSessionURL    string   `json:"end_session_endpoint"`
	IntrospectionURL string   `json:"introspection_endpoint,omitempty"` // OAuth 2.0 Token Introspection (RFC 7662)
	ScopesSupported  []string `json:"scopes_supported,omitempty"`       // Supported scopes from discovery
	RegistrationURL  string   `json:"registration_endpoint,omitempty"`  // OIDC Dynamic Client Registration (RFC 7591)
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
	tokenBlacklist             CacheInterface
	tokenTypeCache             CacheInterface // Cache for token type detection results
	headerTemplates            map[string]*template.Template
	sessionManager             *SessionManager
	tokenCleanupStopChan       chan struct{}
	excludedURLs               map[string]struct{}
	extractClaimsFunc          func(tokenString string) (map[string]any, error)
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
	tokenResilienceManager     *TokenResilienceManager
	goroutineWG                *sync.WaitGroup
	clientSecret               string
	clientID                   string
	audience                   string // Expected JWT audience, defaults to clientID
	roleClaimName              string // JWT claim name for extracting roles, defaults to "roles"
	groupClaimName             string // JWT claim name for extracting groups, defaults to "groups"
	userIdentifierClaim        string // JWT claim for user identification, defaults to "email"
	name                       string
	redirURLPath               string
	logoutURLPath              string
	metadataMu                 sync.RWMutex // Protects metadata endpoint fields
	tokenURL                   string
	authURL                    string
	endSessionURL              string
	postLogoutRedirectURI      string
	scheme                     string
	jwksURL                    string
	issuerURL                  string
	revocationURL              string
	introspectionURL           string // OAuth 2.0 Token Introspection endpoint (RFC 7662)
	providerURL                string
	scopes                     []string
	refreshGracePeriod         time.Duration
	introspectionCache         CacheInterface // Cache for token introspection results
	shutdownOnce               sync.Once
	firstRequestMutex          sync.Mutex
	forceHTTPS                 bool
	enablePKCE                 bool
	overrideScopes             bool
	strictAudienceValidation   bool // Prevents Scenario 2 fallback to ID token
	allowOpaqueTokens          bool // Enables opaque token support via introspection
	requireTokenIntrospection  bool // Forces introspection for opaque tokens
	disableReplayDetection     bool // Disables JTI-based replay detection for multi-replica deployments
	suppressDiagnosticLogs     bool
	firstRequestReceived       bool
	metadataRefreshStarted     bool
	allowPrivateIPAddresses    bool // Allow private IP addresses in URLs (for internal networks)
	minimalHeaders             bool // Reduce headers to prevent 431 errors
	securityHeadersApplier     func(http.ResponseWriter, *http.Request)
	scopeFilter                *ScopeFilter // NEW - for discovery-based scope filtering
	scopesSupported            []string     // NEW - from provider metadata

	// Dynamic Client Registration (RFC 7591)
	dynamicClientRegistrar *DynamicClientRegistrar
	dcrConfig              *DynamicClientRegistrationConfig
	registrationURL        string // OIDC Dynamic Client Registration endpoint
}
