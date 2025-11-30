package token

import (
	"net/http"
	"time"
)

// TokenResponse represents the response from a token endpoint.
// It contains the tokens and additional metadata returned by the OIDC provider.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// JWT represents a parsed JSON Web Token.
// It contains the decoded header and claims from the token.
type JWT struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}

// JWK represents a JSON Web Key used for token verification.
// It contains the cryptographic key material and metadata.
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c,omitempty"`
}

// JWKS represents a JSON Web Key Set.
// It contains multiple public keys that can be used for token verification.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// TokenVerifier interface for verifying tokens
type TokenVerifier interface {
	VerifyToken(token string) error
}

// TokenExchanger interface for exchanging tokens
type TokenExchanger interface {
	GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error)
	ExchangeCodeForToken(ctx interface{}, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error)
}

// ClaimsExtractor function type for extracting claims from tokens
type ClaimsExtractor func(token string) (map[string]interface{}, error)

// CacheInterface defines cache operations for storing token data
type CacheInterface interface {
	Get(key string) (map[string]interface{}, bool)
	Set(key string, value map[string]interface{})
	Delete(key string)
}

// TokenCacheInterface defines methods for token caching operations
type TokenCacheInterface interface {
	CacheToken(token string, claims map[string]interface{})
	GetCachedToken(token string) (map[string]interface{}, bool)
	InvalidateToken(token string)
	StartCleanup(interval time.Duration)
	StopCleanup()
}

// LoggerInterface defines logging methods
type LoggerInterface interface {
	Logf(format string, args ...interface{})
	ErrorLogf(format string, args ...interface{})
}

// MetricsInterface defines metrics tracking methods
type MetricsInterface interface {
	RecordTokenRefresh()
	RecordTokenRefreshError()
}

// SessionManagerInterface defines session management methods
type SessionManagerInterface interface {
	GetSession(sessionID string) (SessionDataInterface, error)
	SaveSession(session SessionDataInterface) error
}

// SessionDataInterface defines minimal session interface needed by refresher
type SessionDataInterface interface {
	GetRefreshToken() string
	GetIDToken() string
	GetAccessToken() string
	GetIDTokenExpiry() time.Time
	GetAccessTokenExpiry() time.Time
	SetIDToken(token string, expiry time.Time)
	SetAccessToken(token string, expiry time.Time)
	SetRefreshToken(token string)
	SetTokens(idToken, accessToken, refreshToken string, idExpiry, accessExpiry time.Time)
	SaveToCache() error
}

// IntrospectorInterface defines methods for token introspection
type IntrospectorInterface interface {
	IntrospectToken(token string, tokenTypeHint string) (*IntrospectionResponse, error)
	ExtractGroupsAndRoles(idToken string) ([]string, []string, error)
	DetectTokenType(token string) (string, error)
}

// IntrospectionResponse represents the response from token introspection
type IntrospectionResponse struct {
	Active    bool                   `json:"active"`
	Scope     string                 `json:"scope,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	Username  string                 `json:"username,omitempty"`
	TokenType string                 `json:"token_type,omitempty"`
	Exp       int64                  `json:"exp,omitempty"`
	Iat       int64                  `json:"iat,omitempty"`
	Nbf       int64                  `json:"nbf,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Aud       interface{}            `json:"aud,omitempty"`
	Iss       string                 `json:"iss,omitempty"`
	Jti       string                 `json:"jti,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// RefresherInterface defines methods for token refresh operations
type RefresherInterface interface {
	RefreshToken(rw http.ResponseWriter, req *http.Request, session SessionDataInterface) bool
	GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error)
}

// RevokeTokenEntry represents a token revocation request
type RevokeTokenEntry struct {
	Token     string
	TokenType string
	RevokedAt time.Time
	Reason    string
}

// ValidatorConfig contains configuration for the token validator
type ValidatorConfig struct {
	ClientID               string
	Audience               string
	IssuerURL              string
	JwksURL                string
	TokenCache             TokenCacheInterface
	TokenBlacklist         CacheInterface
	TokenTypeCache         CacheInterface
	JwkCache               interface{}
	HTTPClient             *http.Client
	Limiter                interface{}
	ExtractClaimsFunc      ClaimsExtractor
	TokenVerifier          TokenVerifier
	DisableReplayDetection bool
	SuppressDiagnosticLogs bool
	MetadataMu             interface{} // sync.RWMutex
	Logger                 interface{}
}

// Constants for token validation
const (
	DefaultBlacklistDuration = 24 * time.Hour
	TokenCacheDuration       = 5 * time.Minute
)

// Token type constants
const (
	TokenTypeAccess  = "ACCESS_TOKEN"
	TokenTypeID      = "ID_TOKEN"
	TokenTypeRefresh = "REFRESH_TOKEN"
	TokenTypeUnknown = "UNKNOWN"
)

// Provider constants
const (
	ProviderGoogle = "google"
	ProviderAzure  = "azure"
	ProviderOkta   = "okta"
	ProviderAuth0  = "auth0"
)
