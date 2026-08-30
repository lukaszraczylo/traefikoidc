// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file implements OAuth 2.0 Token Introspection (RFC 7662) for opaque token validation.
package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IntrospectionResponse represents the response from an OAuth 2.0 token introspection endpoint.
// Per RFC 7662, this contains information about the token's validity and properties.
type IntrospectionResponse struct {
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Sub       string `json:"sub,omitempty"`
	// Aud holds the introspection audience. Per RFC 7662 it may be a single
	// string or an array of strings, so it is decoded as interface{} and
	// matched with verifyAudience (which handles both shapes).
	Aud    interface{} `json:"aud,omitempty"`
	Iss    string      `json:"iss,omitempty"`
	Jti    string      `json:"jti,omitempty"`
	Exp    int64       `json:"exp,omitempty"`
	Iat    int64       `json:"iat,omitempty"`
	Nbf    int64       `json:"nbf,omitempty"`
	Active bool        `json:"active"`
}

// introspectToken performs OAuth 2.0 Token Introspection (RFC 7662) for an opaque token.
// It queries the provider's introspection endpoint to determine token validity and properties.
// Results are cached to minimize repeated introspection requests.
//
// Parameters:
//   - token: The opaque access token to introspect
//
// Returns:
//   - *IntrospectionResponse: The introspection result
//   - error: Any error that occurred during introspection
func (t *TraefikOidc) introspectToken(token string) (*IntrospectionResponse, error) {
	// Check cache first
	if t.introspectionCache != nil {
		if cached, found := t.introspectionCache.Get(token); found {
			if response, ok := cached.(*IntrospectionResponse); ok {
				t.logger.Debugf("Using cached introspection result for token")
				return response, nil
			}
		}
	}

	// Get introspection URL
	t.metadataMu.RLock()
	introspectionURL := t.introspectionURL
	t.metadataMu.RUnlock()

	if introspectionURL == "" {
		return nil, fmt.Errorf("introspection endpoint not available from provider")
	}

	// Prepare introspection request per RFC 7662 Section 2.1
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token") // Hint that it's an access token

	// Create HTTP request
	req, err := http.NewRequestWithContext(context.Background(), "POST", introspectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Authenticate using client credentials (per RFC 7662 Section 2.1)
	// The introspection endpoint requires authentication.
	// Snapshot clientID/clientSecret under metadataMu: DCR rewrites them at
	// runtime (R137).
	clientID, clientSecret, _, _, _ := t.clientCredentials()
	// RFC 7662 §2.1 authenticates the introspection call exactly like the
	// token and revocation endpoints: form-urlencode client_id and
	// client_secret individually before base64 (RFC 6749 §2.3.1), so the
	// three outbound auth paths send identical wire credentials for secrets
	// containing reserved characters (see setOAuthBasicAuth).
	setOAuthBasicAuth(req, clientID, clientSecret)

	// Send request with circuit breaker if available
	var resp *http.Response
	if t.errorRecoveryManager != nil {
		t.metadataMu.RLock()
		serviceName := fmt.Sprintf("token-introspection-%s", t.issuerURL)
		t.metadataMu.RUnlock()

		err = t.errorRecoveryManager.ExecuteWithRecovery(context.Background(), serviceName, func() error {
			var reqErr error
			resp, reqErr = t.httpClient.Do(req) //nolint:bodyclose // Body is closed in defer after error check
			if reqErr != nil && resp != nil && resp.Body != nil {
				_ = resp.Body.Close() // Safe to ignore: closing body on error
			}
			return reqErr
		})
	} else {
		resp, err = t.httpClient.Do(req)
	}

	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close() // Safe to ignore: closing body on error
		}
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body) // Safe to ignore: draining body on defer
			_ = resp.Body.Close()                 // Safe to ignore: closing body on defer
		}
	}()

	// Check HTTP status. Return a typed *HTTPError so callers can
	// distinguish a definite client-side rejection (4xx: the presented
	// token is unknown/revoked -> treat like active=false) from a
	// transient provider failure (5xx / other), instead of substring-
	// matching the message and misclassifying a revoked token as a
	// transient error that falls through to ID-token-only auth (R156).
	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 1024*10)
		body, _ := io.ReadAll(limitReader) // Safe to ignore: reading error body for diagnostics
		return nil, &HTTPError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("introspection endpoint returned status %d: %s", resp.StatusCode, string(body)),
		}
	}

	// Parse response per RFC 7662 Section 2.2
	var introspectionResp IntrospectionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&introspectionResp); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	// Cache the result. Only positive (active) results are cached so a
	// revoked token's negative entry cannot poison the cache for its full TTL
	// Cache the result. Only positive (active) results are cached so a
	// revoked token's negative entry cannot poison the cache for its full TTL
	// and keep rejecting a re-issued token with the same string (R104).
	// Inactive results are re-introspected on each request, letting a
	// re-issued valid token pass immediately.
	if t.introspectionCache != nil && introspectionResp.Active {
		// Cache for a short duration or until token expiry (whichever is shorter)
		cacheDuration := 5 * time.Minute
		// When introspection is REQUIRED, operators expect near-real-time
		// revocation; cap the positive-result cache so a token revoked at the
		// provider cannot keep passing for the full 5 minutes (rank 8).
		if t.requireTokenIntrospection && cacheDuration > 30*time.Second {
			cacheDuration = 30 * time.Second
		}
		if introspectionResp.Exp > 0 {
			expTime := time.Unix(introspectionResp.Exp, 0)
			untilExp := time.Until(expTime)
			if untilExp > 0 && untilExp < cacheDuration {
				cacheDuration = untilExp
			}
		}
		t.introspectionCache.Set(token, &introspectionResp, cacheDuration)
		t.logger.Debugf("Cached introspection result for %v", cacheDuration)
	}

	return &introspectionResp, nil
}

// validateOpaqueToken validates an opaque access token using token introspection.
// It checks if the token is active, not expired, and has the correct audience if specified.
//
// Parameters:
//   - token: The opaque access token to validate
//
// Returns:
//   - error: Validation error if token is invalid, nil if valid
func (t *TraefikOidc) validateOpaqueToken(token string) error {
	// Snapshot clientID/audience under metadataMu: DCR rewrites them at
	// runtime (R137).
	clientID, _, _, audience, _ := t.clientCredentials()
	// Check if opaque tokens are allowed
	if !t.allowOpaqueTokens {
		return fmt.Errorf("opaque tokens are not enabled (set allowOpaqueTokens to true)")
	}

	// Check if introspection is required but not available
	t.metadataMu.RLock()
	introspectionURL := t.introspectionURL
	t.metadataMu.RUnlock()

	if introspectionURL == "" {
		if t.requireTokenIntrospection {
			return fmt.Errorf("token introspection required but endpoint not available")
		}
		// Allow fallback to ID token validation
		t.logger.Debugf("Introspection endpoint not available, will rely on ID token validation")
		return nil
	}

	// Perform introspection
	resp, err := t.introspectToken(token)
	if err != nil {
		return fmt.Errorf("token introspection failed: %w", err)
	}

	// Check if token is active (per RFC 7662 Section 2.2)
	if !resp.Active {
		return fmt.Errorf("token is not active (revoked or expired)")
	}

	// An opaque token has no JWT header to classify it, so token_type is
	// the only discriminator between an access token and a refresh token.
	// An opaque refresh token introspected (or otherwise) as
	// active=true, token_type=refresh_token must not be honored as a
	// bearer access token (R149). RFC 7662's token_type is the RFC 6749
	// token type, whose value for an access token is "Bearer" (RFC 6750)
	// — accept both spellings providers use (R156). Per RFC 7662
	// token_type may be omitted by compliant providers, so only reject on
	// a definite non-access match.
	if resp.TokenType != "" && resp.TokenType != "access_token" && resp.TokenType != "Bearer" {
		return fmt.Errorf("token type %q is not a bearer access token", resp.TokenType)
	}

	// Validate expiration if present
	if resp.Exp > 0 {
		expTime := time.Unix(resp.Exp, 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("token has expired")
		}
	}

	// Validate not-before if present
	if resp.Nbf > 0 {
		nbfTime := time.Unix(resp.Nbf, 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("token not yet valid (nbf)")
		}
	}

	// Validate audience if configured. When a distinct API audience is
	// configured (audience != clientID), the introspection response MUST carry
	// a matching audience. Fail closed on a missing or mismatched aud: a token
	// whose audience cannot be confirmed must not be accepted, otherwise a
	// token minted for a different audience would pass. aud may be a single
	// string or an array of strings (RFC 7662); verifyAudience handles both.
	if audience != "" && audience != clientID {
		if resp.Aud == nil {
			return fmt.Errorf("invalid audience: expected %s, introspection response has no audience", audience)
		}
		if err := verifyAudience(resp.Aud, audience); err != nil {
			return fmt.Errorf("invalid audience: expected %s: %w", audience, err)
		}
	}

	t.logger.Debugf("Opaque token validation successful via introspection")
	return nil
}
