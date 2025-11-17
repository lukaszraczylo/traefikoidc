// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains the core HTTP middleware functionality for request processing
// and authentication flow management.
package traefikoidc

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ============================================================================
// HTTP MIDDLEWARE
// ============================================================================

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
				// Metadata refresh is handled by singleton resource manager
				t.startMetadataRefresh(t.providerURL)
			}
		}
		t.firstRequestMutex.Unlock()
	}

	select {
	case <-t.initComplete:
		// Read issuerURL with RLock
		t.metadataMu.RLock()
		issuerURL := t.issuerURL
		t.metadataMu.RUnlock()

		if issuerURL == "" {
			t.logger.Error("OIDC provider metadata initialization failed or incomplete")
			t.sendErrorResponse(rw, req, "OIDC provider metadata initialization failed - please check provider availability and configuration", http.StatusServiceUnavailable)
			return
		}
	case <-req.Context().Done():
		t.logger.Debug("Request canceled while waiting for OIDC initialization")
		t.sendErrorResponse(rw, req, "Request canceled", http.StatusRequestTimeout)
		return
	case <-time.After(30 * time.Second):
		t.logger.Error("Timeout waiting for OIDC initialization")
		t.sendErrorResponse(rw, req, "Timeout waiting for OIDC provider initialization - please try again later", http.StatusServiceUnavailable)
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

	authHeader := req.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		t.logger.Debug("Bearer token found in Authorization header, processing token authentication")
		token := strings.TrimSpace(authHeader[7:])
		if err := t.verifyToken(token); err != nil {
			t.sendErrorResponse(rw, req, "Unauthorized", http.StatusUnauthorized)
		}
		t.next.ServeHTTP(rw, req)
		return
	}

	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v. Initiating authentication.", err)
		cleanReq := req.Clone(req.Context())
		session, _ = t.sessionManager.GetSession(cleanReq) // Safe to ignore: error already logged, proceeding with new session
		if session != nil {
			defer session.returnToPoolSafely()
			if clearErr := session.Clear(cleanReq, rw); clearErr != nil {
				t.logger.Errorf("Error clearing potentially corrupted session: %v", clearErr)
			}
		} else {
			t.logger.Error("Critical session error: Failed to get even a new session.")
			t.sendErrorResponse(rw, req, "Critical session error", http.StatusInternalServerError)
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
	// Domain restriction check removed debug output
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

	// Check if this is an AJAX request that should receive 401 instead of redirect
	isAjaxRequest := t.isAjaxRequest(req)

	// Check if refresh token is likely expired (older than 6 hours)
	refreshTokenExpired := refreshTokenPresent && t.isRefreshTokenExpired(session)

	shouldAttemptRefresh := needsRefresh && refreshTokenPresent && !refreshTokenExpired

	// If AJAX request and refresh token expired, return 401 immediately
	if isAjaxRequest && refreshTokenExpired {
		t.logger.Debug("AJAX request with expired refresh token, returning 401")
		t.sendErrorResponse(rw, req, "Session expired", http.StatusUnauthorized)
		return
	}

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
		if isAjaxRequest {
			t.logger.Debug("AJAX request with failed token refresh, sending 401 Unauthorized")
			t.sendErrorResponse(rw, req, "Token refresh failed", http.StatusUnauthorized)
		} else {
			t.logger.Debug("Browser request with failed token refresh, initiating re-auth")
			// Reset redirect count when starting fresh auth after failed refresh to prevent redirect loops
			session.ResetRedirectCount()
			t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		}
		return
	}

	t.logger.Debugf("Initiating full OIDC authentication flow (authenticated=%v, needsRefresh=%v, refreshTokenPresent=%v)", authenticated, needsRefresh, refreshTokenPresent)

	// If AJAX request without valid authentication, return 401
	if isAjaxRequest {
		t.logger.Debug("AJAX request requires authentication, sending 401 Unauthorized")
		t.sendErrorResponse(rw, req, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Reset redirect count when starting fresh authentication flow
	session.ResetRedirectCount()
	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// ============================================================================
// REQUEST PROCESSING
// ============================================================================

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
		// Reset redirect count to prevent loops when session is invalid
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	tokenForClaims := session.GetIDToken()
	if tokenForClaims == "" {
		tokenForClaims = session.GetAccessToken()
		if tokenForClaims == "" && len(t.allowedRolesAndGroups) > 0 {
			t.logger.Error("No token available but roles/groups checks are required")
			// Reset redirect count to prevent loops when token is missing
			session.ResetRedirectCount()
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
			// Reset redirect count to prevent loops when claim extraction fails
			session.ResetRedirectCount()
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

	// Apply security headers if configured
	if t.securityHeadersApplier != nil {
		t.securityHeadersApplier(rw, req)
	} else {
		// Fallback to basic security headers
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-XSS-Protection", "1; mode=block")
		rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}

	t.logger.Debugf("Request authorized for user %s, forwarding to next handler", email)

	t.next.ServeHTTP(rw, req)
}
