package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/utils"
)

// Token-mediating backend endpoint (draft-ietf-oauth-browser-based-apps,
// "Token-Mediating Backend"). The spec defines no paths or formats, so the
// endpoint is served only at the path configured in tmbSessionURL,
// authenticated by the regular session cookie, and is never reachable by
// bearer auth. GET reads the session and its access token; POST forces a
// refresh first and returns the same body.

// isTMBPath reports whether path is the configured token-mediating endpoint.
func (t *TraefikOidc) isTMBPath(path string) bool {
	return t.tmbSessionURLPath != "" && path == t.tmbSessionURLPath
}

func writeTMBJSON(rw http.ResponseWriter, status int, body map[string]interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body) // Safe to ignore: response write
}

func writeTMBError(rw http.ResponseWriter, status int, code, description string) {
	body := map[string]interface{}{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	writeTMBJSON(rw, status, body)
}

// tmbCrossSite reports whether the request was issued from another origin.
// Browsers label cross-origin requests with Sec-Fetch-Site and Origin, and no
// CORS headers are ever emitted. Requests carrying neither header
// (non-browser clients) pass.
func tmbCrossSite(req *http.Request) bool {
	switch strings.ToLower(req.Header.Get("Sec-Fetch-Site")) {
	case "cross-site", "same-site":
		return true
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, utils.DetermineHost(req)) {
			return true
		}
	}
	return false
}

// handleTMB serves the token-mediating endpoint. Callers must have verified
// isTMBPath.
func (t *TraefikOidc) handleTMB(rw http.ResponseWriter, req *http.Request) {
	h := rw.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	// The endpoint is same-origin only. The middleware-wide security headers
	// may already have added CORS headers (securityHeaders.corsEnabled); drop
	// them so a cross-origin page can never be granted read access.
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			h.Del(name)
		}
	}

	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		h.Set("Allow", "GET, POST")
		writeTMBError(rw, http.StatusMethodNotAllowed, "invalid_request", "only GET and POST are supported")
		return
	}
	if tmbCrossSite(req) {
		writeTMBError(rw, http.StatusForbidden, "invalid_request", "cross-origin requests are not allowed")
		return
	}

	session, err := t.sessionManager.GetSession(req)
	if err != nil || session == nil {
		t.logger.Errorf("Token-mediating endpoint: no usable session: %v", err)
		writeTMBError(rw, http.StatusUnauthorized, "invalid_session", "")
		return
	}
	gen := session.ownerGeneration()
	defer session.returnToPoolIfOwner(gen)

	rs := (&requestState{metadata: t.metadataSnap()}).captureSession(session)
	refreshed, ok := t.tmbEstablishSession(rw, req, session, rs)
	if !ok {
		return
	}

	claims, groups, roles, ok := t.tmbAuthorize(rw, session)
	if !ok {
		return
	}

	// POST forces a refresh, unless this request already refreshed. The
	// refresh runs only after the user passed the authorization gates, and
	// the gates are re-applied to the refreshed token's claims.
	if req.Method == http.MethodPost && !refreshed {
		// Each forced refresh is an IdP round trip, so it shares the optional
		// per-source throttle of the other auth gates (perSourceLoginRateLimit).
		if t.perSourceLimiter != nil && !t.perSourceLimiter.allow(req) {
			rw.Header().Set("Retry-After", "1")
			writeTMBError(rw, http.StatusTooManyRequests, "rate_limited", "too many refresh requests, try again shortly")
			return
		}
		if !t.tmbForceRefresh(rw, req, session, rs) {
			return
		}
		if claims, groups, roles, ok = t.tmbAuthorize(rw, session); !ok {
			return
		}
	}

	t.writeTMBSession(rw, session, rs, claims, groups, roles)
}

// tmbEstablishSession ensures the session holds a valid, authenticated token
// set, refreshing it when due, and updates rs to match. It reports whether a
// refresh happened. It answers invalid_session itself and returns ok=false
// when no valid session exists. It never redirects: this endpoint is for
// XHR/fetch.
func (t *TraefikOidc) tmbEstablishSession(rw http.ResponseWriter, req *http.Request, session *SessionData, rs *requestState) (refreshed, ok bool) {
	authenticated, needsRefresh, expired := t.isUserAuthenticatedRS(rs)
	if expired {
		writeTMBError(rw, http.StatusUnauthorized, "invalid_session", "")
		return false, false
	}
	if needsRefresh && rs.refreshToken != "" && !t.isRefreshTokenExpired(session) &&
		!(authenticated && t.shouldSkipGraceRefresh(session)) {
		if t.refreshToken(rw, req, session) {
			rs.captureSession(session)
			authenticated, refreshed = true, true
		}
	}
	if !authenticated {
		writeTMBError(rw, http.StatusUnauthorized, "invalid_session", "")
		return false, false
	}
	return refreshed, true
}

// tmbForceRefresh runs a refresh-token grant through the existing refresh
// path and updates rs. It answers the error itself and returns false on
// failure.
func (t *TraefikOidc) tmbForceRefresh(rw http.ResponseWriter, req *http.Request, session *SessionData, rs *requestState) bool {
	if rs.refreshToken == "" {
		writeTMBError(rw, http.StatusUnauthorized, "backend_not_ready", "")
		return false
	}
	if !t.refreshToken(rw, req, session) {
		// A rejected refresh token clears the session; any other failure
		// (IdP unreachable, 5xx) leaves it intact.
		if !session.GetAuthenticated() {
			writeTMBError(rw, http.StatusUnauthorized, "invalid_session", "")
		} else {
			writeTMBError(rw, http.StatusBadGateway, "server_error", "token refresh failed")
		}
		return false
	}
	rs.captureSession(session)
	return true
}

// tmbAuthorize applies the same post-authentication gates as the normal
// request path (identifier present, allowed user, IdP-initiated logout
// invalidation, allowed roles/groups) and returns the token claims.
func (t *TraefikOidc) tmbAuthorize(rw http.ResponseWriter, session *SessionData) (map[string]interface{}, []string, []string, bool) {
	identifier := session.GetUserIdentifier()
	if identifier == "" {
		writeTMBError(rw, http.StatusUnauthorized, "invalid_session", "")
		return nil, nil, nil, false
	}
	if !t.isAllowedUser(identifier) {
		writeTMBError(rw, http.StatusForbidden, "access_denied", "")
		return nil, nil, nil, false
	}
	idToken := session.GetIDToken()
	if idToken != "" && (t.enableBackchannelLogout || t.enableFrontchannelLogout) {
		sid, sub, createdAt := t.invalidationInputs(idToken, session)
		if t.isSessionInvalidated(sid, sub, createdAt) {
			writeTMBError(rw, http.StatusUnauthorized, "invalid_session", "")
			return nil, nil, nil, false
		}
	}

	var claims map[string]interface{}
	if idToken != "" {
		claims, _ = session.GetIDTokenClaims(t.extractClaimsFunc)
	} else if at := session.GetAccessToken(); at != "" {
		claims, _ = t.extractClaimsFunc(at)
	}
	var groups, roles []string
	if claims != nil {
		var err error
		groups, roles, err = t.extractGroupsAndRolesFromClaims(claims)
		if err != nil && len(t.allowedRolesAndGroups) > 0 {
			writeTMBError(rw, http.StatusForbidden, "access_denied", "")
			return nil, nil, nil, false
		}
	}
	if len(t.allowedRolesAndGroups) > 0 {
		allowed := false
		for _, g := range append(append([]string{}, groups...), roles...) {
			if _, ok := t.allowedRolesAndGroups[g]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			writeTMBError(rw, http.StatusForbidden, "access_denied", "")
			return nil, nil, nil, false
		}
	}
	return claims, groups, roles, true
}

// tmbTokenExpiresIn derives expires_in from a JWT access token's exp claim.
// It returns false for opaque tokens.
func tmbTokenExpiresIn(token string) (int64, bool) {
	parsed, err := parseJWT(token)
	if err != nil {
		return 0, false
	}
	exp, ok := parsed.Claims["exp"].(float64)
	if !ok {
		return 0, false
	}
	left := int64(exp) - time.Now().Unix()
	if left < 0 {
		left = 0
	}
	return left, true
}

// writeTMBSession answers 200 with the session information and the access
// token.
func (t *TraefikOidc) writeTMBSession(rw http.ResponseWriter, session *SessionData, rs *requestState, claims map[string]interface{}, groups, roles []string) {
	out := map[string]interface{}{
		"authenticated":   true,
		"user_identifier": session.GetUserIdentifier(),
	}
	// Only the claims the operator listed in tmbClaims, as they appear in the
	// token; absent or null claims are left out.
	shown := map[string]interface{}{}
	for _, name := range t.tmbClaims {
		if v, ok := claims[name]; ok && v != nil {
			shown[name] = v
		}
	}
	if len(shown) > 0 {
		out["claims"] = shown
	}
	if len(groups) > 0 {
		out["groups"] = groups
	}
	if len(roles) > 0 {
		out["roles"] = roles
	}
	if exp, ok := claims["exp"].(float64); ok {
		out["expires_at"] = int64(exp)
	}
	if rs.accessToken != "" {
		out["access_token"] = rs.accessToken
		if n, ok := tmbTokenExpiresIn(rs.accessToken); ok {
			out["expires_in"] = n
		}
	}
	writeTMBJSON(rw, http.StatusOK, out)
}
