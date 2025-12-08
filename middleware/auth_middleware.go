// Package middleware provides authentication middleware for OIDC flows
package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthMiddleware handles the main OIDC authentication flow
type AuthMiddleware struct {
	logger                    Logger
	next                      http.Handler
	sessionManager            SessionManager
	authHandler               AuthHandler
	oauthHandler              OAuthHandler
	urlHelper                 URLHelper
	tokenVerifier             TokenVerifier
	extractClaimsFunc         func(tokenString string) (map[string]interface{}, error)
	extractGroupsAndRolesFunc func(tokenString string) ([]string, []string, error)
	sendErrorResponseFunc     func(rw http.ResponseWriter, req *http.Request, message string, code int)
	refreshTokenFunc          func(rw http.ResponseWriter, req *http.Request, session SessionData) bool
	isUserAuthenticatedFunc   func(session SessionData) (bool, bool, bool)
	isAllowedDomainFunc       func(email string) bool
	isAjaxRequestFunc         func(req *http.Request) bool
	isRefreshTokenExpiredFunc func(session SessionData) bool
	processLogoutFunc         func(rw http.ResponseWriter, req *http.Request)
	excludedURLs              map[string]struct{}
	allowedRolesAndGroups     map[string]struct{}
	redirURLPath              string
	logoutURLPath             string
	refreshGracePeriod        time.Duration
	initComplete              chan struct{}
	issuerURL                 string
	firstRequestReceived      bool
	metadataRefreshStarted    bool
	firstRequestMutex         sync.Mutex
	providerURL               string
	goroutineWG               *sync.WaitGroup
	startTokenCleanupFunc     func()
	startMetadataRefreshFunc  func(string)
	minimalHeaders            bool
}

// Logger interface for dependency injection
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
}

// SessionManager interface for session operations
type SessionManager interface {
	CleanupOldCookies(rw http.ResponseWriter, req *http.Request)
	GetSession(req *http.Request) (SessionData, error)
}

// SessionData interface for session data operations
type SessionData interface {
	GetEmail() string
	GetAccessToken() string
	GetIDToken() string
	GetRefreshToken() string
	Clear(req *http.Request, rw http.ResponseWriter) error
	ResetRedirectCount()
	returnToPoolSafely()
}

// AuthHandler interface for authentication operations
type AuthHandler interface {
	InitiateAuthentication(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string,
		generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error))
}

// OAuthHandler interface for OAuth callback operations
type OAuthHandler interface {
	HandleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string)
}

// URLHelper interface for URL operations
type URLHelper interface {
	DetermineExcludedURL(currentRequest string, excludedURLs map[string]struct{}) bool
	DetermineScheme(req *http.Request) string
	DetermineHost(req *http.Request) string
}

// TokenVerifier interface for token verification
type TokenVerifier interface {
	VerifyToken(token string) error
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(
	logger Logger,
	next http.Handler,
	sessionManager SessionManager,
	authHandler AuthHandler,
	oauthHandler OAuthHandler,
	urlHelper URLHelper,
	tokenVerifier TokenVerifier,
	extractClaimsFunc func(string) (map[string]interface{}, error),
	extractGroupsAndRolesFunc func(string) ([]string, []string, error),
	sendErrorResponseFunc func(http.ResponseWriter, *http.Request, string, int),
	refreshTokenFunc func(http.ResponseWriter, *http.Request, SessionData) bool,
	isUserAuthenticatedFunc func(SessionData) (bool, bool, bool),
	isAllowedDomainFunc func(string) bool,
	isAjaxRequestFunc func(*http.Request) bool,
	isRefreshTokenExpiredFunc func(SessionData) bool,
	processLogoutFunc func(http.ResponseWriter, *http.Request),
	excludedURLs map[string]struct{},
	allowedRolesAndGroups map[string]struct{},
	redirURLPath, logoutURLPath string,
	refreshGracePeriod time.Duration,
	initComplete chan struct{},
	issuerURL, providerURL string,
	goroutineWG *sync.WaitGroup,
	startTokenCleanupFunc func(),
	startMetadataRefreshFunc func(string),
	minimalHeaders bool,
) *AuthMiddleware {
	return &AuthMiddleware{
		logger:                    logger,
		next:                      next,
		sessionManager:            sessionManager,
		authHandler:               authHandler,
		oauthHandler:              oauthHandler,
		urlHelper:                 urlHelper,
		tokenVerifier:             tokenVerifier,
		extractClaimsFunc:         extractClaimsFunc,
		extractGroupsAndRolesFunc: extractGroupsAndRolesFunc,
		sendErrorResponseFunc:     sendErrorResponseFunc,
		refreshTokenFunc:          refreshTokenFunc,
		isUserAuthenticatedFunc:   isUserAuthenticatedFunc,
		isAllowedDomainFunc:       isAllowedDomainFunc,
		isAjaxRequestFunc:         isAjaxRequestFunc,
		isRefreshTokenExpiredFunc: isRefreshTokenExpiredFunc,
		processLogoutFunc:         processLogoutFunc,
		excludedURLs:              excludedURLs,
		allowedRolesAndGroups:     allowedRolesAndGroups,
		redirURLPath:              redirURLPath,
		logoutURLPath:             logoutURLPath,
		refreshGracePeriod:        refreshGracePeriod,
		initComplete:              initComplete,
		issuerURL:                 issuerURL,
		providerURL:               providerURL,
		goroutineWG:               goroutineWG,
		startTokenCleanupFunc:     startTokenCleanupFunc,
		startMetadataRefreshFunc:  startMetadataRefreshFunc,
		minimalHeaders:            minimalHeaders,
	}
}

// ServeHTTP implements the main OIDC authentication middleware
func (m *AuthMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !strings.HasPrefix(req.URL.Path, "/health") {
		m.firstRequestMutex.Lock()
		if !m.firstRequestReceived {
			m.firstRequestReceived = true
			m.logger.Debug("Starting background tasks on first request")
			m.startTokenCleanupFunc()

			if !m.metadataRefreshStarted && m.providerURL != "" {
				m.metadataRefreshStarted = true
				// Metadata refresh is now handled by singleton resource manager
				// Just call the function directly - it will use the singleton internally
				m.startMetadataRefreshFunc(m.providerURL)
			}
		}
		m.firstRequestMutex.Unlock()
	}

	select {
	case <-m.initComplete:
		if m.issuerURL == "" {
			m.logger.Error("OIDC provider metadata initialization failed or incomplete")
			m.sendErrorResponseFunc(rw, req, "OIDC provider metadata initialization failed - please check provider availability and configuration", http.StatusServiceUnavailable)
			return
		}
	case <-req.Context().Done():
		m.logger.Debug("Request canceled while waiting for OIDC initialization")
		m.sendErrorResponseFunc(rw, req, "Request canceled", http.StatusRequestTimeout)
		return
	case <-time.After(30 * time.Second):
		m.logger.Error("Timeout waiting for OIDC initialization")
		m.sendErrorResponseFunc(rw, req, "Timeout waiting for OIDC provider initialization - please try again later", http.StatusServiceUnavailable)
		return
	}

	if m.urlHelper.DetermineExcludedURL(req.URL.Path, m.excludedURLs) {
		m.logger.Debugf("Request path %s excluded by configuration, bypassing OIDC", req.URL.Path)
		m.next.ServeHTTP(rw, req)
		return
	}

	acceptHeader := req.Header.Get("Accept")
	if strings.Contains(acceptHeader, "text/event-stream") {
		m.logger.Debugf("Request accepts text/event-stream (%s), bypassing OIDC", acceptHeader)
		m.next.ServeHTTP(rw, req)
		return
	}

	m.sessionManager.CleanupOldCookies(rw, req)

	session, err := m.sessionManager.GetSession(req)
	if err != nil {
		m.logger.Errorf("Error getting session: %v. Initiating authentication.", err)
		cleanReq := req.Clone(req.Context())
		session, _ = m.sessionManager.GetSession(cleanReq)
		if session != nil {
			defer session.returnToPoolSafely()
			if clearErr := session.Clear(cleanReq, rw); clearErr != nil {
				m.logger.Errorf("Error clearing potentially corrupted session: %v", clearErr)
			}
		} else {
			m.logger.Error("Critical session error: Failed to get even a new session.")
			m.sendErrorResponseFunc(rw, req, "Critical session error", http.StatusInternalServerError)
			return
		}
		scheme := m.urlHelper.DetermineScheme(req)
		host := m.urlHelper.DetermineHost(req)
		redirectURL := buildFullURL(scheme, host, m.redirURLPath)
		m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
			generateNonce, generateCodeVerifier, deriveCodeChallenge)
		return
	}

	defer session.returnToPoolSafely()

	scheme := m.urlHelper.DetermineScheme(req)
	host := m.urlHelper.DetermineHost(req)
	redirectURL := buildFullURL(scheme, host, m.redirURLPath)

	if req.URL.Path == m.logoutURLPath {
		m.processLogoutFunc(rw, req)
		return
	}
	if req.URL.Path == m.redirURLPath {
		m.oauthHandler.HandleCallback(rw, req, redirectURL)
		return
	}

	authenticated, needsRefresh, expired := m.isUserAuthenticatedFunc(session)

	if expired {
		m.logger.Debug("Session token is definitively expired or invalid, initiating re-auth")
		m.handleExpiredToken(rw, req, session, redirectURL)
		return
	}

	email := session.GetEmail()
	if authenticated && email != "" {
		if !m.isAllowedDomainFunc(email) {
			m.logger.Infof("User with email %s is not from an allowed domain", email)
			errorMsg := fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", m.logoutURLPath)
			m.sendErrorResponseFunc(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	if authenticated && !needsRefresh {
		m.logger.Debug("User authenticated and token valid, proceeding to process authorized request")
		// Access token validation is already performed by provider-specific validation
		// methods (validateAzureTokens/validateStandardTokens) before reaching this point.
		// Redundant validation here was causing issues with Azure AD tokens that have
		// JWT format but unverifiable signatures. See issue #89.
		m.processAuthorizedRequest(rw, req, session, redirectURL)
		return
	}

	m.handleRefreshFlow(rw, req, session, redirectURL, needsRefresh, authenticated)
}

// handleExpiredToken handles expired tokens by initiating re-authentication
func (m *AuthMiddleware) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string) {
	session.ResetRedirectCount()
	m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
		generateNonce, generateCodeVerifier, deriveCodeChallenge)
}

// handleRefreshFlow handles token refresh flow or initiates authentication
func (m *AuthMiddleware) handleRefreshFlow(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string, needsRefresh, authenticated bool) {
	refreshTokenPresent := session.GetRefreshToken() != ""
	isAjaxRequest := m.isAjaxRequestFunc(req)
	refreshTokenExpired := refreshTokenPresent && m.isRefreshTokenExpiredFunc(session)
	shouldAttemptRefresh := needsRefresh && refreshTokenPresent && !refreshTokenExpired

	// If AJAX request and refresh token expired, return 401 immediately
	if isAjaxRequest && refreshTokenExpired {
		m.logger.Debug("AJAX request with expired refresh token, returning 401")
		m.sendErrorResponseFunc(rw, req, "Session expired", http.StatusUnauthorized)
		return
	}

	if shouldAttemptRefresh {
		m.handleTokenRefresh(rw, req, session, redirectURL, needsRefresh, authenticated, isAjaxRequest)
		return
	}

	m.logger.Debugf("Initiating full OIDC authentication flow (authenticated=%v, needsRefresh=%v, refreshTokenPresent=%v)", authenticated, needsRefresh, refreshTokenPresent)

	// If AJAX request without valid authentication, return 401
	if isAjaxRequest {
		m.logger.Debug("AJAX request requires authentication, sending 401 Unauthorized")
		m.sendErrorResponseFunc(rw, req, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Reset redirect count when starting fresh authentication flow
	session.ResetRedirectCount()
	m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
		generateNonce, generateCodeVerifier, deriveCodeChallenge)
}

// handleTokenRefresh handles the token refresh process
func (m *AuthMiddleware) handleTokenRefresh(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string, needsRefresh, authenticated, isAjaxRequest bool) {
	if needsRefresh && authenticated {
		m.logger.Debug("Session token needs proactive refresh, attempting refresh")
	} else if needsRefresh && !authenticated {
		m.logger.Debug("ID token invalid/expired, but refresh token found. Attempting refresh.")
	}

	refreshed := m.refreshTokenFunc(rw, req, session)
	if refreshed {
		email := session.GetEmail()
		if email != "" && !m.isAllowedDomainFunc(email) {
			m.logger.Infof("User with refreshed token email %s is not from an allowed domain", email)
			errorMsg := fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", m.logoutURLPath)
			m.sendErrorResponseFunc(rw, req, errorMsg, http.StatusForbidden)
			return
		}

		m.logger.Debug("Token refresh successful, proceeding to process authorized request")
		m.processAuthorizedRequest(rw, req, session, redirectURL)
		return
	}

	m.logger.Debug("Token refresh failed, requiring re-authentication")
	if isAjaxRequest {
		m.logger.Debug("AJAX request with failed token refresh, sending 401 Unauthorized")
		m.sendErrorResponseFunc(rw, req, "Token refresh failed", http.StatusUnauthorized)
	} else {
		m.logger.Debug("Browser request with failed token refresh, initiating re-auth")
		// Reset redirect count when starting fresh auth after failed refresh to prevent redirect loops
		session.ResetRedirectCount()
		m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
			generateNonce, generateCodeVerifier, deriveCodeChallenge)
	}
}

// processAuthorizedRequest processes requests for authenticated users
func (m *AuthMiddleware) processAuthorizedRequest(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string) {
	email := session.GetEmail()
	if email == "" {
		m.logger.Info("No email found in session during final processing, initiating re-auth")
		// Reset redirect count to prevent loops when session is invalid
		session.ResetRedirectCount()
		m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
			generateNonce, generateCodeVerifier, deriveCodeChallenge)
		return
	}

	tokenForClaims := session.GetIDToken()
	if tokenForClaims == "" {
		tokenForClaims = session.GetAccessToken()
		if tokenForClaims == "" && len(m.allowedRolesAndGroups) > 0 {
			m.logger.Error("No token available but roles/groups checks are required")
			// Reset redirect count to prevent loops when token is missing
			session.ResetRedirectCount()
			m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
				generateNonce, generateCodeVerifier, deriveCodeChallenge)
			return
		}
	}

	// Initialize empty slices
	var groups, roles []string

	if tokenForClaims != "" {
		var err error
		groups, roles, err = m.extractGroupsAndRolesFunc(tokenForClaims)
		if err != nil && len(m.allowedRolesAndGroups) > 0 {
			m.logger.Errorf("Failed to extract groups and roles: %v", err)
			// Reset redirect count to prevent loops when claim extraction fails
			session.ResetRedirectCount()
			m.authHandler.InitiateAuthentication(rw, req, session, redirectURL,
				generateNonce, generateCodeVerifier, deriveCodeChallenge)
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

	if len(m.allowedRolesAndGroups) > 0 {
		allowed := false
		for _, roleOrGroup := range append(groups, roles...) {
			if _, ok := m.allowedRolesAndGroups[roleOrGroup]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			m.logger.Infof("User with email %s does not have any allowed roles or groups", email)
			errorMsg := fmt.Sprintf("Access denied: You do not have any of the allowed roles or groups. To log out, visit: %s", m.logoutURLPath)
			m.sendErrorResponseFunc(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	req.Header.Set("X-Forwarded-User", email)

	// When minimalHeaders is enabled, skip extra headers to prevent 431 errors
	if !m.minimalHeaders {
		req.Header.Set("X-Auth-Request-Redirect", req.URL.RequestURI())
		req.Header.Set("X-Auth-Request-User", email)
		if idToken := session.GetIDToken(); idToken != "" {
			req.Header.Set("X-Auth-Request-Token", idToken)
		}
	}

	m.next.ServeHTTP(rw, req)
}

// buildFullURL constructs a full URL from scheme, host, and path components
func buildFullURL(scheme, host, path string) string {
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// These functions need to be provided by the calling code or injected as dependencies
func generateNonce() (string, error) {
	// This function needs to be implemented or injected
	return "", fmt.Errorf("generateNonce not implemented")
}

func generateCodeVerifier() (string, error) {
	// This function needs to be implemented or injected
	return "", fmt.Errorf("generateCodeVerifier not implemented")
}

func deriveCodeChallenge() (string, error) {
	// This function needs to be implemented or injected
	return "", fmt.Errorf("deriveCodeChallenge not implemented")
}
