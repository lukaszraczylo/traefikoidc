// Package traefikoidc provides OIDC authentication middleware for Traefik.
package traefikoidc

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
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
	IntrospectionURL string   `json:"introspection_endpoint,omitempty"`
	RegistrationURL  string   `json:"registration_endpoint,omitempty"`
	ScopesSupported  []string `json:"scopes_supported,omitempty"`
}

// TraefikOidc is the main middleware struct that implements OIDC authentication for Traefik.
// It integrates with various OIDC providers, manages sessions, caches tokens, and handles
// the complete authentication flow. It's designed to work seamlessly with Traefik's
// plugin system and provides flexible configuration options.
// MetadataSnapshot is an immutable bundle of provider-metadata URLs that the
// plugin needs on the hot request path. Published atomically via
// TraefikOidc.metadataSnapshot; readers do exactly one atomic.Value.Load to
// access all fields. Replaces 3 per-request metadataMu.RLock acquisitions
// in middleware.ServeHTTP + token_manager paths, each of which paid
// 1-5ms of Yaegi-dispatch overhead.
//
// The fields are a strict subset of the metadataMu-guarded TraefikOidc
// fields; the legacy fields are still written under metadataMu for
// less-frequent code paths that have not been migrated.
type MetadataSnapshot struct {
	IssuerURL        string
	JWKSURL          string
	TokenURL         string
	AuthURL          string
	RevocationURL    string
	EndSessionURL    string
	IntrospectionURL string
	RegistrationURL  string
}

type TraefikOidc struct {
	// metadataSnapshot atomically publishes the read-mostly URL bundle.
	// Hot-path readers (middleware.ServeHTTP, token verification) load it
	// directly; less-frequent paths still acquire metadataMu.RLock and
	// read the individual fields below.
	metadataSnapshot           atomic.Value
	// lastMetadataRetryNano is the UnixNano timestamp of the last metadata
	// recovery attempt. Stored atomically so the hot ServeHTTP path can
	// throttle retries without acquiring metadataRetryMutex on every request.
	lastMetadataRetryNano      int64
	// firstRequestStarted is 0 until the very first non-health request fires
	// the background-task bootstrap; then it flips to 1 via CAS. Replaces the
	// firstRequestMutex + firstRequestReceived combo which previously took
	// a write lock on every non-health request forever.
	firstRequestStarted        int32
	// metadataRefreshStartedAtomic is the CAS-only variant of the old
	// metadataRefreshStarted bool. Both flags live under the same atomic so
	// concurrent first-request goroutines race exactly once.
	metadataRefreshStartedAtomic int32
	jwkCache                   JWKCacheInterface
	jwtVerifier                JWTVerifier
	ctx                        context.Context
	tokenVerifier              TokenVerifier
	next                       http.Handler
	tokenExchanger             TokenExchanger
	tokenBlacklist             CacheInterface
	tokenTypeCache             CacheInterface
	introspectionCache         CacheInterface
	initComplete               chan struct{}
	limiter                    *rate.Limiter
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
	refreshCoordinator         *RefreshCoordinator
	goroutineWG                *sync.WaitGroup
	dcrConfig                  *DynamicClientRegistrationConfig
	dynamicClientRegistrar     *DynamicClientRegistrar
	scopeFilter                *ScopeFilter
	securityHeadersApplier     func(http.ResponseWriter, *http.Request)
	userIdentifierClaim        string
	revocationURL              string
	name                       string
	redirURLPath               string
	logoutURLPath              string
	tokenURL                   string
	authURL                    string
	endSessionURL              string
	postLogoutRedirectURI      string
	jwksURL                    string
	issuerURL                  string
	groupClaimName             string
	introspectionURL           string
	providerURL                string
	roleClaimName              string
	audience                   string
	clientID                   string
	clientSecret               string
	clientAuthMethod           string
	clientAssertion            *ClientAssertionSigner
	registrationURL            string
	backchannelLogoutPath      string
	frontchannelLogoutPath     string
	scopesSupported            []string
	scopes                     []string
	extraAuthParams            map[string]string
	refreshGracePeriod         time.Duration
	maxRefreshTokenAge         time.Duration
	metadataMu                 sync.RWMutex
	shutdownOnce               sync.Once
	sessionInvalidationCache   CacheInterface
	refreshResultCache         CacheInterface
	minimalHeaders             bool
	stripAuthCookies           bool
	enableBackchannelLogout    bool
	enableFrontchannelLogout   bool
	requireTokenIntrospection  bool
	allowPrivateIPAddresses    bool
	disableReplayDetection     bool
	allowOpaqueTokens          bool
	strictAudienceValidation   bool
	overrideScopes             bool
	enablePKCE                 bool
	forceHTTPS                 bool
	suppressDiagnosticLogs     bool

	// Bearer-auth runtime state (populated only when EnableBearerAuth=true).
	bearerIdentifierClaim     string
	bearerFailureTracker      *bearerFailureTracker
	maxTokenAge               time.Duration
	maxIdentifierLength       int
	bearerFailureThreshold    int
	bearerFailureWindow       time.Duration
	bearerFailurePenalty      time.Duration
	enableBearerAuth          bool
	stripAuthorizationHeader  bool
	bearerEmitWWWAuthenticate bool
	bearerOverridesCookie     bool
}
