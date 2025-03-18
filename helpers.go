package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// generateNonce creates a cryptographically secure random nonce
// for use in the OIDC authentication flow. The nonce is used to
// prevent replay attacks by ensuring the token received matches
// the authentication request.
func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

// generateCodeVerifier creates a cryptographically secure random string
// for use as a PKCE code verifier. The code verifier must be between 43 and 128
// characters long, per the PKCE spec (RFC 7636).
func generateCodeVerifier() (string, error) {
	// Using 32 bytes (256 bits) will produce a 43 character base64url string
	verifierBytes := make([]byte, 32)
	_, err := rand.Read(verifierBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(verifierBytes), nil
}

// deriveCodeChallenge creates a code challenge from a code verifier
// using the SHA-256 method as specified in the PKCE standard (RFC 7636).
func deriveCodeChallenge(codeVerifier string) string {
	// Calculate SHA-256 hash of the code verifier
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	hash := hasher.Sum(nil)

	// Base64url encode the hash to get the code challenge
	return base64.RawURLEncoding.EncodeToString(hash)
}

// TokenResponse represents the response from the OIDC token endpoint.
// It contains the various tokens and metadata returned after successful
// code exchange or token refresh operations.
type TokenResponse struct {
	// IDToken is the OIDC ID token containing user claims
	IDToken string `json:"id_token"`

	// AccessToken is the OAuth 2.0 access token for API access
	AccessToken string `json:"access_token"`

	// RefreshToken is the OAuth 2.0 refresh token for obtaining new tokens
	RefreshToken string `json:"refresh_token"`

	// ExpiresIn is the lifetime in seconds of the access token
	ExpiresIn int `json:"expires_in"`

	// TokenType is the type of token, typically "Bearer"
	TokenType string `json:"token_type"`
}

// exchangeTokens performs the OAuth 2.0 token exchange with the OIDC provider.
// It supports both authorization code and refresh token grant types.
// Parameters:
//   - ctx: Context for the HTTP request
//   - grantType: The OAuth 2.0 grant type ("authorization_code" or "refresh_token")
//   - codeOrToken: Either the authorization code or refresh token
//   - redirectURL: The callback URL for authorization code grant
//   - codeVerifier: Optional PKCE code verifier for authorization code grant
func (t *TraefikOidc) exchangeTokens(ctx context.Context, grantType, codeOrToken, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {grantType},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}

	if grantType == "authorization_code" {
		data.Set("code", codeOrToken)
		data.Set("redirect_uri", redirectURL)

		// Add code_verifier if PKCE is being used
		if codeVerifier != "" {
			data.Set("code_verifier", codeVerifier)
		}
	} else if grantType == "refresh_token" {
		data.Set("refresh_token", codeOrToken)
	}

	// Create a cookie jar for this request to handle redirects with cookies
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: t.httpClient.Transport,
		Timeout:   t.httpClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Always follow redirects for OIDC endpoints
			if len(via) >= 50 {
				return fmt.Errorf("stopped after 50 redirects")
			}
			return nil
		},
		Jar: jar,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// getNewTokenWithRefreshToken obtains new tokens using a refresh token.
// This is used to refresh access tokens before they expire.
func (t *TraefikOidc) getNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	ctx := context.Background()
	tokenResponse, err := t.exchangeTokens(ctx, "refresh_token", refreshToken, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	t.logger.Debugf("Token response: %+v", tokenResponse)
	return tokenResponse, nil
}

// handleExpiredToken manages token expiration by clearing the session
// and initiating a new authentication flow.
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	// Clear authentication data but preserve CSRF state
	session.SetAuthenticated(false)
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetEmail("")

	// Save the cleared session state
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save cleared session: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// handleCallback processes the authentication callback from the OIDC provider.
// It validates the callback parameters, exchanges the authorization code for
// tokens, verifies the tokens, and establishes the user's session.
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	// Check for errors in the callback
	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		t.logger.Errorf("Authentication error: %s - %s", req.URL.Query().Get("error"), errorDescription)
		http.Error(rw, fmt.Sprintf("Authentication error: %s", errorDescription), http.StatusBadRequest)
		return
	}

	// Validate CSRF state
	state := req.URL.Query().Get("state")
	if state == "" {
		t.logger.Error("No state in callback")
		http.Error(rw, "State parameter missing in callback", http.StatusBadRequest)
		return
	}

	csrfToken := session.GetCSRF()
	if csrfToken == "" {
		t.logger.Error("CSRF token missing in session")
		http.Error(rw, "CSRF token missing", http.StatusBadRequest)
		return
	}

	if state != csrfToken {
		t.logger.Error("State parameter does not match CSRF token in session")
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		http.Error(rw, "No code in callback", http.StatusBadRequest)
		return
	}

	// Get the code verifier from the session for PKCE flow
	codeVerifier := session.GetCodeVerifier()

	tokenResponse, err := t.exchangeCodeForTokenFunc(code, redirectURL, codeVerifier)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Verify tokens and claims
	if err := t.verifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Verify nonce to prevent replay attacks
	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		t.logger.Error("Nonce claim does not match session nonce")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Validate user's email domain
	email, _ := claims["email"].(string)
	if email == "" || !t.isAllowedDomain(email) {
		t.logger.Errorf("Invalid or disallowed email: %s", email)
		http.Error(rw, "Authentication failed: Invalid or disallowed email", http.StatusForbidden)
		return
	}

	// Update session with authentication data
	session.SetAuthenticated(true)
	session.SetEmail(email)
	session.SetAccessToken(tokenResponse.IDToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}
// Redirect to original path or root
redirectPath := "/"
if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != t.redirURLPath {
	redirectPath = incomingPath
}

// For redirecting, we need to ensure URL fragments are preserved
// To do this, we'll use a small JavaScript snippet that preserves any URL fragments
// This is necessary because URL fragments are not sent to the server
rw.Header().Set("Content-Type", "text/html; charset=utf-8")
rw.WriteHeader(http.StatusOK)
fmt.Fprintf(rw, `<!DOCTYPE html>
<html>
<head>
<title>Authentication Complete</title>
<script>
// Preserve URL fragments by combining the redirectPath with any fragment in the current URL
(function() {
 var redirectPath = %q;
 var redirectUrl = new URL(redirectPath, window.location.href);
 
 // If we have a hash in the current URL, and the redirect path doesn't already have one,
 // append the hash to the redirect URL to preserve anchors
 if (window.location.hash && !redirectPath.includes('#')) {
   redirectUrl.hash = window.location.hash;
 }
 
 window.location.replace(redirectUrl.toString());
})();
</script>
</head>
<body>
<p>Authentication successful. Redirecting...</p>
</body>
</html>`, redirectPath)
	http.Redirect(rw, req, redirectPath, http.StatusFound)
}

// extractClaims parses a JWT token and extracts its claims.
// It handles base64url decoding and JSON parsing of the token payload.
func extractClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

// TokenCache provides a caching mechanism for validated tokens.
// It stores token claims to avoid repeated validation of the
// same token, improving performance for frequently used tokens.
type TokenCache struct {
	// cache is the underlying cache implementation
	cache *Cache
}

// NewTokenCache creates a new TokenCache instance.
func NewTokenCache() *TokenCache {
	return &TokenCache{
		cache: NewCache(),
	}
}

// Set stores a token's claims in the cache with an expiration time.
func (tc *TokenCache) Set(token string, claims map[string]interface{}, expiration time.Duration) {
	token = "t-" + token
	tc.cache.Set(token, claims, expiration)
}

// Get retrieves a token's claims from the cache.
// Returns the claims and a boolean indicating if the token was found.
func (tc *TokenCache) Get(token string) (map[string]interface{}, bool) {
	token = "t-" + token
	value, found := tc.cache.Get(token)
	if !found {
		return nil, false
	}
	claims, ok := value.(map[string]interface{})
	return claims, ok
}

// Delete removes a token from the cache.
func (tc *TokenCache) Delete(token string) {
	token = "t-" + token
	tc.cache.Delete(token)
}

// Cleanup removes expired tokens from the cache.
func (tc *TokenCache) Cleanup() {
	tc.cache.Cleanup()
}

// exchangeCodeForToken exchanges an authorization code for tokens.
// It handles PKCE (Proof Key for Code Exchange) based on middleware configuration.
// The code verifier is only included in the token request if PKCE is enabled.
func (t *TraefikOidc) exchangeCodeForToken(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	ctx := context.Background()

	// Only include code verifier if PKCE is enabled
	effectiveCodeVerifier := ""
	if t.enablePKCE && codeVerifier != "" {
		effectiveCodeVerifier = codeVerifier
	}

	tokenResponse, err := t.exchangeTokens(ctx, "authorization_code", code, redirectURL, effectiveCodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return tokenResponse, nil
}

// createStringMap creates a map from a slice of strings.
// Used for efficient lookups in allowed domains and roles.
func createStringMap(keys []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}

// handleLogout manages the OIDC logout process.
// It clears the session and redirects either to the OIDC provider's
// end session endpoint (if available) or to the configured post-logout URL.
func (t *TraefikOidc) handleLogout(rw http.ResponseWriter, req *http.Request) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	accessToken := session.GetAccessToken()

	if err := session.Clear(req, rw); err != nil {
		t.logger.Errorf("Error clearing session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	host := t.determineHost(req)
	scheme := t.determineScheme(req)
	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	postLogoutRedirectURI := t.postLogoutRedirectURI
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = fmt.Sprintf("%s/", baseURL)
	} else if !strings.HasPrefix(postLogoutRedirectURI, "http") {
		postLogoutRedirectURI = fmt.Sprintf("%s%s", baseURL, postLogoutRedirectURI)
	}

	if t.endSessionURL != "" && accessToken != "" {
		logoutURL, err := BuildLogoutURL(t.endSessionURL, accessToken, postLogoutRedirectURI)
		if err != nil {
			t.logger.Errorf("Failed to build logout URL: %v", err)
			http.Error(rw, "Logout error", http.StatusInternalServerError)
			return
		}
		http.Redirect(rw, req, logoutURL, http.StatusFound)
		return
	}

	http.Redirect(rw, req, postLogoutRedirectURI, http.StatusFound)
}

// BuildLogoutURL constructs the OIDC end session URL with appropriate parameters.
// Parameters:
//   - endSessionURL: The OIDC provider's end session endpoint
//   - idToken: The ID token to be invalidated
//   - postLogoutRedirectURI: Where to redirect after logout completes
func BuildLogoutURL(endSessionURL, idToken, postLogoutRedirectURI string) (string, error) {
	u, err := url.Parse(endSessionURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse end session URL: %w", err)
	}

	q := u.Query()
	q.Set("id_token_hint", idToken)
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}
