package servers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil/fixtures"
)

// OIDCServerConfig configures the mock OIDC server behavior
type OIDCServerConfig struct {
	JWKSResponse             map[string]interface{}
	TokenFixture             *fixtures.TokenFixture
	UserinfoError            *OIDCError
	UserinfoResponse         map[string]interface{}
	IntrospectionResponse    map[string]interface{}
	JWKSError                *OIDCError
	RefreshError             *OIDCError
	TokenResponse            map[string]interface{}
	TokenError               *OIDCError
	IntrospectionError       *OIDCError
	RefreshResponse          map[string]interface{}
	Issuer                   string
	GrantTypesSupported      []string
	TokenEndpointAuthMethods []string
	ScopesSupported          []string
	ClaimsSupported          []string
	ResponseTypesSupported   []string
	FailAfterN               int
	JWKSDelay                time.Duration
	TimeoutDuration          time.Duration
	RateLimitAfter           int
	TokenDelay               time.Duration
	FailWithStatus           int
	SimulateTimeout          bool
}

// OIDCError represents an OAuth error response
type OIDCError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// OIDCServer is a configurable mock OIDC provider
type OIDCServer struct {
	*httptest.Server
	Config       *OIDCServerConfig
	requests     []*http.Request
	mu           sync.Mutex
	RequestCount int32
}

// NewOIDCServer creates a new mock OIDC server
func NewOIDCServer(config *OIDCServerConfig) *OIDCServer {
	if config == nil {
		config = DefaultConfig()
	}

	server := &OIDCServer{
		Config: config,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", server.handleDiscovery)
	mux.HandleFunc("/token", server.handleToken)
	mux.HandleFunc("/jwks", server.handleJWKS)
	mux.HandleFunc("/authorize", server.handleAuthorize)
	mux.HandleFunc("/userinfo", server.handleUserinfo)
	mux.HandleFunc("/revoke", server.handleRevoke)
	mux.HandleFunc("/introspect", server.handleIntrospect)
	mux.HandleFunc("/logout", server.handleLogout)

	server.Server = httptest.NewServer(mux)

	// Update issuer to use actual server URL if not set
	if config.Issuer == "" {
		config.Issuer = server.URL
	}

	return server
}

// NewTLSServer creates a new mock OIDC server with TLS
func NewTLSServer(config *OIDCServerConfig) *OIDCServer {
	if config == nil {
		config = DefaultConfig()
	}

	server := &OIDCServer{
		Config: config,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", server.handleDiscovery)
	mux.HandleFunc("/token", server.handleToken)
	mux.HandleFunc("/jwks", server.handleJWKS)
	mux.HandleFunc("/authorize", server.handleAuthorize)
	mux.HandleFunc("/userinfo", server.handleUserinfo)
	mux.HandleFunc("/revoke", server.handleRevoke)
	mux.HandleFunc("/introspect", server.handleIntrospect)
	mux.HandleFunc("/logout", server.handleLogout)

	server.Server = httptest.NewTLSServer(mux)

	if config.Issuer == "" {
		config.Issuer = server.URL
	}

	return server
}

// GetRequestCount returns the number of requests received
func (s *OIDCServer) GetRequestCount() int {
	return int(atomic.LoadInt32(&s.RequestCount))
}

// GetRequests returns all recorded requests
func (s *OIDCServer) GetRequests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// Reset clears request tracking
func (s *OIDCServer) Reset() {
	atomic.StoreInt32(&s.RequestCount, 0)
	s.mu.Lock()
	s.requests = nil
	s.mu.Unlock()
}

func (s *OIDCServer) recordRequest(r *http.Request) {
	atomic.AddInt32(&s.RequestCount, 1)
	s.mu.Lock()
	s.requests = append(s.requests, r)
	s.mu.Unlock()
}

func (s *OIDCServer) shouldFail() bool {
	count := int(atomic.LoadInt32(&s.RequestCount))
	if s.Config.FailAfterN > 0 && count > s.Config.FailAfterN {
		return true
	}
	if s.Config.RateLimitAfter > 0 && count > s.Config.RateLimitAfter {
		return true
	}
	return false
}

func (s *OIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	if s.Config.SimulateTimeout {
		time.Sleep(s.Config.TimeoutDuration)
		return
	}

	discovery := map[string]interface{}{
		"issuer":                                s.Config.Issuer,
		"authorization_endpoint":                s.Config.Issuer + "/authorize",
		"token_endpoint":                        s.Config.Issuer + "/token",
		"userinfo_endpoint":                     s.Config.Issuer + "/userinfo",
		"jwks_uri":                              s.Config.Issuer + "/jwks",
		"revocation_endpoint":                   s.Config.Issuer + "/revoke",
		"introspection_endpoint":                s.Config.Issuer + "/introspect",
		"end_session_endpoint":                  s.Config.Issuer + "/logout",
		"scopes_supported":                      s.Config.ScopesSupported,
		"response_types_supported":              s.Config.ResponseTypesSupported,
		"grant_types_supported":                 s.Config.GrantTypesSupported,
		"claims_supported":                      s.Config.ClaimsSupported,
		"token_endpoint_auth_methods_supported": s.Config.TokenEndpointAuthMethods,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(discovery) // #nosec G104 - test server, error handling not critical
}

func (s *OIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	if s.Config.SimulateTimeout {
		time.Sleep(s.Config.TimeoutDuration)
		return
	}

	if s.Config.TokenDelay > 0 {
		time.Sleep(s.Config.TokenDelay)
	}

	if s.shouldFail() {
		status := http.StatusTooManyRequests
		if s.Config.FailWithStatus > 0 {
			status = s.Config.FailWithStatus
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(OIDCError{Error: "rate_limited"}) // #nosec G104
		return
	}

	if s.Config.TokenError != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(s.Config.TokenError) // #nosec G104
		return
	}

	_ = r.ParseForm() // #nosec G104
	grantType := r.FormValue("grant_type")

	var response map[string]interface{}

	if grantType == "refresh_token" {
		if s.Config.RefreshError != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(s.Config.RefreshError) // #nosec G104
			return
		}
		response = s.Config.RefreshResponse
	} else {
		response = s.Config.TokenResponse
	}

	if response == nil {
		response = s.defaultTokenResponse()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response) // #nosec G104
}

func (s *OIDCServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	if s.Config.SimulateTimeout {
		time.Sleep(s.Config.TimeoutDuration)
		return
	}

	if s.Config.JWKSDelay > 0 {
		time.Sleep(s.Config.JWKSDelay)
	}

	if s.Config.JWKSError != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(s.Config.JWKSError) // #nosec G104
		return
	}

	response := s.Config.JWKSResponse
	if response == nil && s.Config.TokenFixture != nil {
		response = s.Config.TokenFixture.GetJWKS()
	}
	if response == nil {
		response = map[string]interface{}{"keys": []interface{}{}}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response) // #nosec G104
}

func (s *OIDCServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	// In real flow, this would redirect with code
	// For testing, we return a simple page
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	// Validate redirect URI to prevent open redirect vulnerability
	if !isValidRedirectURI(redirectURI, s.URL) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	redirectURL := fmt.Sprintf("%s?code=test-auth-code&state=%s", redirectURI, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *OIDCServer) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	if s.Config.UserinfoError != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(s.Config.UserinfoError) // #nosec G104
		return
	}

	response := s.Config.UserinfoResponse
	if response == nil {
		response = map[string]interface{}{
			"sub":   "test-subject",
			"email": "user@example.com",
			"name":  "Test User",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response) // #nosec G104
}

func (s *OIDCServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)
	w.WriteHeader(http.StatusOK)
}

func (s *OIDCServer) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	if s.Config.IntrospectionError != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(s.Config.IntrospectionError) // #nosec G104
		return
	}

	response := s.Config.IntrospectionResponse
	if response == nil {
		response = map[string]interface{}{
			"active":    true,
			"sub":       "test-subject",
			"client_id": "test-client",
			"exp":       time.Now().Add(time.Hour).Unix(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response) // #nosec G104
}

func (s *OIDCServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.recordRequest(r)

	postLogoutRedirect := r.URL.Query().Get("post_logout_redirect_uri")
	if postLogoutRedirect != "" {
		// Validate post-logout redirect URI to prevent open redirect vulnerability
		if !isValidRedirectURI(postLogoutRedirect, s.URL) {
			http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, postLogoutRedirect, http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Logged out")) // #nosec G104
}

func (s *OIDCServer) defaultTokenResponse() map[string]interface{} {
	var idToken string
	if s.Config.TokenFixture != nil {
		idToken, _ = s.Config.TokenFixture.ValidToken(nil)
	} else {
		idToken = "mock-id-token"
	}

	return map[string]interface{}{
		"access_token":  "mock-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "mock-refresh-token",
		"id_token":      idToken,
	}
}

// isValidRedirectURI validates that a redirect URI is safe to use.
// It ensures the URI is either:
// 1. A relative path (no scheme or host)
// 2. Points to the same host as the test server (localhost)
// 3. Points to a common test domain (127.0.0.1, localhost)
// This prevents open redirect vulnerabilities in the test server.
func isValidRedirectURI(redirectURI, serverURL string) bool {
	if redirectURI == "" {
		return false
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	// Allow relative paths (no scheme means relative)
	if parsed.Scheme == "" && parsed.Host == "" {
		return true
	}

	// Parse the server URL to get its host
	serverParsed, err := url.Parse(serverURL)
	if err != nil {
		return false
	}

	// Allow same host as test server
	if parsed.Host == serverParsed.Host {
		return true
	}

	// Allow common localhost variations used in tests
	host := strings.ToLower(parsed.Hostname())
	allowedHosts := []string{
		"localhost",
		"127.0.0.1",
		"[::1]",
		"example.com", // Common test domain
		"myapp.com",   // Common test domain
		"test.example.com",
	}

	for _, allowed := range allowedHosts {
		if host == allowed {
			return true
		}
	}

	return false
}

// DefaultConfig returns a default server configuration
func DefaultConfig() *OIDCServerConfig {
	return &OIDCServerConfig{
		ScopesSupported:          []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported:   []string{"code", "token", "id_token"},
		GrantTypesSupported:      []string{"authorization_code", "refresh_token"},
		ClaimsSupported:          []string{"sub", "email", "name", "groups", "roles"},
		TokenEndpointAuthMethods: []string{"client_secret_basic", "client_secret_post"},
		TimeoutDuration:          30 * time.Second,
	}
}

// GoogleConfig returns a Google-like server configuration
func GoogleConfig() *OIDCServerConfig {
	config := DefaultConfig()
	config.Issuer = "https://accounts.google.com"
	config.ScopesSupported = []string{"openid", "profile", "email"}
	// Google doesn't support offline_access, uses access_type=offline instead
	return config
}

// AzureConfig returns an Azure AD-like server configuration
func AzureConfig() *OIDCServerConfig {
	config := DefaultConfig()
	config.Issuer = "https://login.microsoftonline.com/common/v2.0"
	config.ScopesSupported = []string{"openid", "profile", "email", "offline_access"}
	return config
}

// Auth0Config returns an Auth0-like server configuration
func Auth0Config() *OIDCServerConfig {
	config := DefaultConfig()
	config.ScopesSupported = []string{"openid", "profile", "email", "offline_access"}
	return config
}

// KeycloakConfig returns a Keycloak-like server configuration
func KeycloakConfig() *OIDCServerConfig {
	config := DefaultConfig()
	config.ScopesSupported = []string{"openid", "profile", "email", "offline_access", "roles", "groups"}
	return config
}

// SlowServerConfig returns a configuration that simulates slow responses
func SlowServerConfig(delay time.Duration) *OIDCServerConfig {
	config := DefaultConfig()
	config.TokenDelay = delay
	config.JWKSDelay = delay
	return config
}

// RateLimitedConfig returns a configuration that rate limits after N requests
func RateLimitedConfig(afterN int) *OIDCServerConfig {
	config := DefaultConfig()
	config.RateLimitAfter = afterN
	return config
}

// FailingConfig returns a configuration that fails after N requests
func FailingConfig(afterN int, status int) *OIDCServerConfig {
	config := DefaultConfig()
	config.FailAfterN = afterN
	config.FailWithStatus = status
	return config
}

// TimeoutConfig returns a configuration that simulates timeouts
func TimeoutConfig(duration time.Duration) *OIDCServerConfig {
	config := DefaultConfig()
	config.SimulateTimeout = true
	config.TimeoutDuration = duration
	return config
}
