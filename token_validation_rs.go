// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains requestState-aware variants of the token validation
// functions. They read session field values from the captured snapshot in
// *requestState instead of calling session.GetX(), eliminating ~21 RLock
// acquisitions on sd.sessionMutex per request through the validation path
// (validateStandardTokens reads 17, validateAzureTokens reads 10,
// validateTokenExpiry reads 4 — and many are the SAME field). Under Yaegi
// each RLock costs ~1-5ms of interpreter dispatch.
//
// The non-RS variants are retained for paths that don't have a captured
// snapshot (tests that drive the validators directly, the Azure/Google path
// when reached without rs threading, etc).
package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// isUserAuthenticatedRS is the requestState-aware variant of
// isUserAuthenticated. Dispatches to the right per-provider validator based
// on the configured provider, all of which read from rs instead of session.
func (t *TraefikOidc) isUserAuthenticatedRS(rs *requestState) (bool, bool, bool) {
	if t.isAzureProvider() {
		return t.validateAzureTokensRS(rs)
	} else if t.isGoogleProvider() {
		return t.validateGoogleTokensRS(rs)
	}
	return t.validateStandardTokensRS(rs)
}

// validateGoogleTokensRS handles Google-specific token validation. Currently
// delegates to standard token validation; retained as a hook for any future
// Google-specific behavior (matches the v1.0.20 layout of the non-RS variant).
func (t *TraefikOidc) validateGoogleTokensRS(rs *requestState) (bool, bool, bool) {
	return t.validateStandardTokensRS(rs)
}

// validateTokenExpiryRS is the requestState-aware variant of validateTokenExpiry.
// Reads rs.refreshToken instead of session.GetRefreshToken() (4 RLocks avoided).
func (t *TraefikOidc) validateTokenExpiryRS(rs *requestState, token string) (bool, bool, bool) {
	cachedClaims, found := t.tokenCache.Get(token)
	if !found {
		t.logger.Debug("Claims not found in cache after successful token verification")
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, true
	}

	expClaim, ok := cachedClaims["exp"].(float64)
	if !ok {
		t.logger.Error("Failed to get expiration time ('exp' claim) from verified token")
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, true
	}

	expTimeObj := time.Unix(int64(expClaim), 0)
	nowObj := time.Now()

	if expTimeObj.Before(nowObj) {
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, true
	}

	refreshThreshold := nowObj.Add(t.refreshGracePeriod)
	if expTimeObj.Before(refreshThreshold) {
		if rs.refreshToken != "" {
			return true, true, false
		}
		return true, false, false
	}

	return true, false, false
}

// validateStandardTokensRS is the requestState-aware variant of
// validateStandardTokens. Replaces all session.GetX() calls (17 of them in
// the non-RS variant, dominated by GetRefreshToken called 11 times) with
// rs field reads. Same control flow.
//
//nolint:gocognit,gocyclo // Mirrors validateStandardTokens complexity by design.
func (t *TraefikOidc) validateStandardTokensRS(rs *requestState) (bool, bool, bool) {
	if !rs.authenticated {
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, false
	}

	if rs.accessToken == "" {
		if rs.refreshToken != "" {
			// ID-token grace-period check (only when accessToken is absent).
			if rs.idToken != "" {
				parts := strings.Split(rs.idToken, ".")
				if len(parts) == 3 {
					if claimsData, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
						var claims map[string]interface{}
						if err := json.Unmarshal(claimsData, &claims); err == nil {
							if expClaim, ok := claims["exp"].(float64); ok {
								expTime := time.Unix(int64(expClaim), 0)
								if time.Now().After(expTime) {
									expiredDuration := time.Since(expTime)
									if expiredDuration > t.refreshGracePeriod {
										return false, false, true
									}
								}
							}
						}
					}
				}
			}
			return false, true, false
		}
		return false, false, true
	}

	dotCount := strings.Count(rs.accessToken, ".")
	isOpaqueToken := dotCount != 2

	if isOpaqueToken {
		if t.allowOpaqueTokens {
			if err := t.validateOpaqueToken(rs.accessToken); err != nil {
				errMsg := err.Error()
				isTokenInvalid := strings.Contains(errMsg, "token is not active") ||
					strings.Contains(errMsg, "revoked") ||
					strings.Contains(errMsg, "token has expired")
				if isTokenInvalid {
					if rs.refreshToken != "" {
						return false, true, false
					}
					return false, false, true
				}
				if t.requireTokenIntrospection {
					if rs.refreshToken != "" {
						return false, true, false
					}
					return false, false, true
				}
				// Transient introspection error: fall through to ID-token validation.
			} else {
				// Introspection succeeded.
				if rs.idToken != "" {
					return t.validateTokenExpiryRS(rs, rs.idToken)
				}
				return true, false, false
			}
		}

		// Fall back to ID-token validation when opaque + no successful introspection.
		if rs.idToken == "" {
			if rs.refreshToken != "" {
				return false, true, false
			}
			return true, false, false
		}
		if err := t.verifyToken(rs.idToken); err != nil {
			if strings.Contains(err.Error(), "token has expired") {
				if rs.refreshToken != "" {
					return false, true, false
				}
				return false, false, true
			}
			if rs.refreshToken != "" {
				return false, true, false
			}
			return false, false, true
		}
		return t.validateTokenExpiryRS(rs, rs.idToken)
	}

	// JWT access token present.
	accessTokenValid := false
	if err := t.verifyToken(rs.accessToken); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid audience") || strings.Contains(errMsg, "audience") {
			if t.strictAudienceValidation {
				if rs.refreshToken != "" {
					return false, true, false
				}
				return false, false, true
			}
			// Fall through to ID-token validation.
		}
	} else {
		accessTokenValid = true
	}

	if rs.idToken == "" {
		if accessTokenValid {
			return t.validateTokenExpiryRS(rs, rs.accessToken)
		}
		if rs.refreshToken != "" {
			return true, true, false
		}
		return true, false, false
	}

	if err := t.verifyToken(rs.idToken); err != nil {
		if strings.Contains(err.Error(), "token has expired") {
			if rs.refreshToken != "" {
				return false, true, false
			}
			return false, false, true
		}
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, true
	}

	if accessTokenValid {
		return t.validateTokenExpiryRS(rs, rs.accessToken)
	}
	return t.validateTokenExpiryRS(rs, rs.idToken)
}

// validateAzureTokensRS is the requestState-aware variant of validateAzureTokens.
// Eliminates 10 session.GetX() RLocks per Azure-path request.
func (t *TraefikOidc) validateAzureTokensRS(rs *requestState) (bool, bool, bool) {
	if !rs.authenticated {
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, true, false
	}

	if rs.accessToken != "" {
		if strings.Count(rs.accessToken, ".") == 2 {
			if t.isUnverifiableAzureAccessToken(rs.accessToken) {
				if rs.idToken != "" {
					if err := t.verifyToken(rs.idToken); err != nil {
						if rs.refreshToken != "" {
							return false, true, false
						}
						return false, false, true
					}
					return t.validateTokenExpiryRS(rs, rs.idToken)
				}
				return true, false, false
			}
			if err := t.verifyToken(rs.accessToken); err != nil {
				if rs.idToken != "" {
					if err := t.verifyToken(rs.idToken); err != nil {
						if rs.refreshToken != "" {
							return false, true, false
						}
						return false, false, true
					}
					return t.validateTokenExpiryRS(rs, rs.idToken)
				}
				if rs.refreshToken != "" {
					return false, true, false
				}
				return false, false, true
			}
			return t.validateTokenExpiryRS(rs, rs.accessToken)
		}
		// Opaque access token.
		if rs.idToken != "" {
			return t.validateTokenExpiryRS(rs, rs.idToken)
		}
		return true, false, false
	}

	if rs.idToken != "" {
		if err := t.verifyToken(rs.idToken); err != nil {
			if rs.refreshToken != "" {
				return false, true, false
			}
			return false, false, true
		}
		return t.validateTokenExpiryRS(rs, rs.idToken)
	}

	if rs.refreshToken != "" {
		return false, true, false
	}
	return false, false, true
}
