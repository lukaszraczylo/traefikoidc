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

// generateNonce creates a cryptographically secure random nonce for OIDC flows.
// The nonce is used to prevent replay attacks and associate client sessions with ID tokens.
// Returns:
//   - A base64 URL-encoded nonce string (43 characters)
//   - An error if the random byte generation fails
func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

// generateCodeVerifier creates a PKCE code verifier according to RFC 7636.
// The code verifier is a cryptographically random string used for the PKCE flow
// to prevent authorization code interception attacks.
// Returns:
//   - A base64 raw URL-encoded code verifier string (43 characters)
//   - An error if the random byte generation fails
func generateCodeVerifier() (string, error) {
	verifierBytes := make([]byte, 32)
	_, err := rand.Read(verifierBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(verifierBytes), nil
}

// deriveCodeChallenge creates a PKCE code challenge from the code verifier.
// It computes the SHA-256 hash of the code verifier and base64 URL-encodes it
// according to RFC 7636 specification.
// Parameters:
//   - codeVerifier: The code verifier string
//
// Returns:
//   - The base64 URL encoded SHA-256 hash of the code verifier (code challenge)
func deriveCodeChallenge(codeVerifier string) string {
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	hash := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(hash)
}

// TokenResponse represents the standard OAuth 2.0/OIDC token response.
// It contains the tokens and metadata returned by the authorization server during
// code exchange or token refresh operations.
type TokenResponse struct {
	// IDToken contains the OpenID Connect identity token (JWT)
	IDToken string `json:"id_token"`
	// AccessToken is the OAuth 2.0 access token for API access
	AccessToken string `json:"access_token"`
	// RefreshToken allows obtaining new tokens when the access token expires
	RefreshToken string `json:"refresh_token"`
	// TokenType specifies the token type (typically "Bearer")
	TokenType string `json:"token_type"`
	// ExpiresIn indicates token lifetime in seconds
	ExpiresIn int `json:"expires_in"`
}

// exchangeTokens performs OAuth 2.0 token exchange with the authorization server.
// It supports both authorization code and refresh token grant types with PKCE support.
// Parameters:
//   - ctx: Context for request timeout and cancellation
//   - grantType: OAuth grant type ("authorization_code" or "refresh_token")
//   - codeOrToken: Authorization code or refresh token depending on grant type
//   - redirectURL: Redirect URI used in authorization (required for code exchange)
//   - codeVerifier: PKCE code verifier (optional, used with PKCE flow)
//
// Returns:
//   - *TokenResponse: Parsed token response from the authorization server
//   - An error if the token exchange fails (e.g., network error, provider error, invalid grant)
func (t *TraefikOidc) exchangeTokens(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {grantType},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}

	if grantType == "authorization_code" {
		data.Set("code", codeOrToken)
		data.Set("redirect_uri", redirectURL)

		if codeVerifier != "" {
			data.Set("code_verifier", codeVerifier)
		}
	} else if grantType == "refresh_token" {
		data.Set("refresh_token", codeOrToken)
	}

	client := t.tokenHTTPClient
	if client == nil {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{
			Transport: t.httpClient.Transport,
			Timeout:   t.httpClient.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 50 {
					return fmt.Errorf("stopped after 50 redirects")
				}
				return nil
			},
			Jar: jar,
		}
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
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 1024*10)
		bodyBytes, _ := io.ReadAll(limitReader)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// getNewTokenWithRefreshToken refreshes access and ID tokens using a refresh token.
// This is used when the current tokens are expired but the refresh token is still valid.
// Parameters:
//   - refreshToken: The refresh token to exchange for new tokens
//
// Returns:
//   - *TokenResponse: New token set from the authorization server
//   - An error if the refresh operation fails
func (t *TraefikOidc) getNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	ctx := context.Background()
	tokenResponse, err := t.exchangeTokens(ctx, "refresh_token", refreshToken, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	t.logger.Debugf("Token response: %+v", tokenResponse)
	return tokenResponse, nil
}

// extractClaims extracts and parses claims from a JWT token without signature verification.
// This is a utility function for quickly accessing token payload data when signature
// verification is not required or has already been performed.
// Parameters:
//   - tokenString: The JWT token string to parse
//
// Returns:
//   - map[string]interface{}: Parsed claims from the token payload
//   - An error if the token format is invalid, decoding fails, or JSON unmarshaling fails
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

// TokenCache provides a specialized cache for JWT tokens and their parsed claims.
// It wraps the base Cache with token-specific prefixing to prevent
// key collisions and provides a clean interface for token caching operations.
type TokenCache struct {
	// cache is the underlying generic cache implementation
	cache CacheInterface
}

// Default configuration constants for the token cache.
const (
	// defaultTokenCacheMaxSize limits the number of cached tokens
	defaultTokenCacheMaxSize = 1000
)

// NewTokenCache creates and initializes a new TokenCache with default settings.
// The cache is configured with a maximum size and automatic cleanup of expired entries.
func NewTokenCache() *TokenCache {
	config := DefaultUnifiedCacheConfig()
	config.MaxSize = defaultTokenCacheMaxSize
	unifiedCache := NewUnifiedCache(config)
	cacheAdapter := NewCacheAdapter(unifiedCache)

	return &TokenCache{
		cache: cacheAdapter,
	}
}

// Set stores parsed token claims in the cache with expiration.
// The token is prefixed to prevent collisions with other cache entries.
// Parameters:
//   - token: The JWT token string (used as cache key)
//   - claims: Parsed claims from the token
//   - expiration: The duration for which the cache entry should be valid
func (tc *TokenCache) Set(token string, claims map[string]interface{}, expiration time.Duration) {
	token = "t-" + token
	tc.cache.Set(token, claims, expiration)
}

// Get retrieves cached claims for a token.
// Parameters:
//   - token: The JWT token string to look up
//
// Returns:
//   - map[string]interface{}: The cached claims if found
//   - A boolean indicating whether the token was found in the cache (true if found, false otherwise)
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
// Parameters:
//   - token: The raw token string to remove from the cache
func (tc *TokenCache) Delete(token string) {
	token = "t-" + token
	tc.cache.Delete(token)
}

// Cleanup removes expired entries from the token cache.
// This is typically called automatically but can be invoked manually for
// removing expired token entries.
func (tc *TokenCache) Cleanup() {
	if tc != nil && tc.cache != nil {
		tc.cache.Cleanup()
	}
}

// Close stops the cleanup goroutine and releases resources.
// Should be called when the token cache is no longer needed.
func (tc *TokenCache) Close() {
	tc.cache.Close()
}

// exchangeCodeForToken exchanges an authorization code for tokens.
// This implements the OAuth 2.0 authorization code flow with optional PKCE support.
// Parameters:
//   - code: The authorization code received from the authorization server
//   - redirectURL: The redirect URI used in the authorization request
//   - codeVerifier: PKCE code verifier (used if PKCE is enabled)
//
// Returns:
//   - *TokenResponse: The token response containing access, refresh, and ID tokens
//   - An error if the code exchange fails
func (t *TraefikOidc) exchangeCodeForToken(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	ctx := context.Background()

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

// createStringMap converts a slice of strings to a set-like map for fast lookups.
// This is a utility function for creating efficient membership tests.
// Parameters:
//   - keys: Slice of strings to convert to a map
//
// Returns:
//   - A map where the keys are the strings from the input slice and the values are empty structs
func createStringMap(keys []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}

// handleLogout processes user logout requests and performs proper session cleanup.
// It retrieves the ID token for logout URL construction, clears the session,
// and redirects to the provider's logout endpoint or configured post-logout URI.
// It handles potential errors during session retrieval or clearing.
func (t *TraefikOidc) handleLogout(rw http.ResponseWriter, req *http.Request) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	idToken := session.GetIDToken()

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

	if t.endSessionURL != "" && idToken != "" {
		logoutURL, err := BuildLogoutURL(t.endSessionURL, idToken, postLogoutRedirectURI)
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

// BuildLogoutURL constructs a logout URL for the OIDC provider's end session endpoint.
// It includes the ID token hint and post-logout redirect URI according to OIDC specifications.
// Parameters:
//   - endSessionURL: The provider's logout/end session endpoint
//   - idToken: The ID token to include as a hint
//   - postLogoutRedirectURI: Where to redirect after logout
//
// Returns:
//   - The complete logout URL with query parameters
//   - An error if the provided endSessionURL is invalid
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

// deduplicateScopes removes duplicate scopes from a slice while preserving order.
// This ensures that OAuth scope parameters don't contain duplicates which could
// cause issues with some authorization servers.
// The first occurrence of each scope is kept.
func deduplicateScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{})
	result := []string{}
	for _, scope := range scopes {
		if _, ok := seen[scope]; !ok {
			seen[scope] = struct{}{}
			result = append(result, scope)
		}
	}
	return result
}
