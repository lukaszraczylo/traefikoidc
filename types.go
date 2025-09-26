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
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	RevokeURL     string `json:"revocation_endpoint"`
	EndSessionURL string `json:"end_session_endpoint"`
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
	securityHeadersApplier     func(http.ResponseWriter, *http.Request)
}
