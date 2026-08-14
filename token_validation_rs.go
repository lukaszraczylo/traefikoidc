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
	"errors"
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

// accessTokenUnexpired reports whether a signature-verified access
// token's time claims still hold. Used on the lenient-audience path where
// jwt.Verify short-circuits at the aud check BEFORE reaching exp/iat/nbf
// validation, leaving all time claims unvalidated. Re-apply the same
// clock-skew-aware checks the main path applies (verifyExpiration,
// verifyIssuedAt with iat required, and verifyNotBefore when present) so a
// token that is expired, used before its issue time, or not yet valid (nbf)
// is not trusted for authorization here.
func (t *TraefikOidc) accessTokenUnexpired(token string) bool {
	parsed, err := parseJWT(token)
	if err != nil {
		return false
	}
	claims := parsed.Claims

	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	if err := verifyExpiration(exp); err != nil {
		return false
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return false
	}
	if err := verifyIssuedAt(iat); err != nil {
		return false
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		if err := verifyNotBefore(nbf); err != nil {
			return false
		}
	}

	return true
}

// validateTokenExpiryRS is the requestState-aware variant of validateTokenExpiry.
// Reads rs.refreshToken instead of session.GetRefreshToken() (4 RLocks avoided).
func (t *TraefikOidc) validateTokenExpiryRS(rs *requestState, token string) (bool, bool, bool) {
	// Defense-in-depth (F2/R133): this is the final authenticated gate.
	// Every current caller has already passed the blacklist check via
	// verifyToken, but guard independently so a revoked-but-still-cached
	// token can never be served authenticated if the call order changes.
	if t.tokenBlacklist != nil {
		if b, ok := t.tokenBlacklist.Get(token); ok && b != nil {
			if rs.refreshToken != "" {
				return false, true, false
			}
			return false, false, true
		}
	}

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

	// Apply the same clock-skew leeway as jwt.Verify's verifyExpiration
	// (ClockSkewToleranceFuture). This is the final auth gate run after
	// successful signature verification; without the leeway a token
	// within the 2-minute post-exp window was granted by Verify but
	// downgraded to here as expired, forcing a needless refresh or
	// re-auth (R124).
	if nowObj.After(expTimeObj.Add(ClockSkewToleranceFuture)) {
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
				// A definitive 4xx from the introspection endpoint (e.g. 401
				// for an unknown/revoked token) means the token itself is bad,
				// not that the endpoint transiently failed. Treat it as
				// invalid (refresh) rather than falling through to
				// ID-token-only auth, which would authenticate a revoked
				// opaque token (R156).
				var httpErr *HTTPError
				if errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
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
				// No ID token to corroborate an access token we cannot verify
				// (Azure nonce-bearing Graph access tokens carry a proprietary,
				// client-unverifiable signature). Do NOT authenticate on an
				// unverified token: refresh if a refresh token is available,
				// otherwise force re-authentication.
				if rs.refreshToken != "" {
					return false, true, false
				}
				return false, false, true
			}
		}

		// Fall back to ID-token validation when opaque + no successful introspection.
		if rs.idToken == "" {
			if rs.refreshToken != "" {
				return false, true, false
			}
			// Opaque access token, no ID token to corroborate it, and
			// introspection was unavailable/disabled/errored (e.g.
			// circuit-breaker open). There is nothing left to verify the token
			// against, so fail closed and force re-authentication rather than
			// trusting an unverified opaque token.
			return false, false, true
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
	lenientAudienceOnly := false
	var accessVerifyErr error
	if err := t.verifyToken(rs.accessToken); err != nil {
		accessVerifyErr = err
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid audience") || strings.Contains(errMsg, "audience") {
			if t.strictAudienceValidation {
				if rs.refreshToken != "" {
					return false, true, false
				}
				return false, false, true
			}
			// Lenient audience validation: the token's signature verified; only
			// the audience was left unchecked. Fall through to ID-token
			// validation, remembering the access token was structurally valid.
			lenientAudienceOnly = true
		}
	} else {
		accessTokenValid = true
	}

	if rs.idToken == "" {
		if accessTokenValid {
			return t.validateTokenExpiryRS(rs, rs.accessToken)
		}
		if lenientAudienceOnly {
			// Access token signature verified; audience check was lenient and
			// there is no ID token to compare against. jwt.Verify returns at
			// the aud check BEFORE reaching the exp check, so expiry was never
			// validated on this path — an expired, wrong-audience token would
			// otherwise be accepted as authenticated. Require the token's time
			// claims (exp, iat, nbf) to all still hold before trusting its
			// claims for authorization.
			if !t.accessTokenUnexpired(rs.accessToken) {
				if rs.refreshToken != "" {
					return false, true, false
				}
				return false, false, true
			}
			if rs.refreshToken != "" {
				return true, true, false
			}
			return true, false, false
		}
		// Access token failed verification (expired, bad signature, issuer, ...)
		// and there is no ID token to corroborate it. Fail closed rather than
		// trusting an unverified token: refresh if possible, otherwise force
		// re-authentication.
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, true
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
	// Access token is a JWT whose verification failed, yet the session's
	// ID token is still valid. If the failure was specifically EXPIRY —
	// verifyToken checks the signature before exp, so "token has expired"
	// implies the signature and other claims validated — the access token
	// is unusable at the upstream resource. Refresh to obtain a fresh one
	// rather than forwarding a stale access token (R131). Without this an
	// expired access token (with a still-valid ID token) was authenticated
	// with needsRefresh=false and forwarded as-is until the ID token
	// itself neared expiry, giving the backend an expired bearer token.
	if accessVerifyErr != nil && strings.Contains(accessVerifyErr.Error(), "token has expired") {
		if rs.refreshToken != "" {
			return true, true, false
		}
		return false, false, true
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
		// No refresh token to use: match the standard path and fail without
		// pretending refresh is possible (the previous copy-paste returned
		// needsRefresh=true with nothing to refresh with).
		return false, false, false
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
				// No ID token to corroborate the Azure token. Its signature
				// can't be verified client-side, but it still carries exp;
				// authenticate only while unexpired. Previously this
				// returned authenticated=true with no expiry check, so an
				// expired (or unparseable) Azure access token authenticated
				// indefinitely until the session itself expired (R129).
				if claims, err := extractClaims(rs.accessToken); err != nil {
					if rs.refreshToken != "" {
						return false, true, false
					}
					return false, false, true
				} else {
					// Defense-in-depth (mirrors validateTokenExpiryRS): a
					// revoked-but-still-cached token must not authenticate
					// through this unverifiable branch either (R147).
					if t.tokenBlacklist != nil {
						if b, ok := t.tokenBlacklist.Get(rs.accessToken); ok && b != nil {
							if rs.refreshToken != "" {
								return false, true, false
							}
							return false, false, true
						}
					}
					// exp must be present and numeric to establish the token
					// is current; an unverifiable token with no (or
					// non-numeric) exp authenticates with zero verification,
					// so fail closed when it can't be bounded (R130).
					exp, ok := claims["exp"].(float64)
					if !ok || time.Now().After(time.Unix(int64(exp), 0).Add(ClockSkewToleranceFuture)) {
						if rs.refreshToken != "" {
							return false, true, false
						}
						return false, false, true
					}
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
		// Opaque access token with no ID token to corroborate it. Do not
		// authenticate on an unverified (or unverifiable) token: refresh
		// if a refresh token is available, otherwise force
		// re-authentication. Mirrors validateStandardTokensRS, which
		// documents this exact decision ("Do NOT authenticate on an
		// unverified token"). The previous `return true, false, false`
		// accepted any opaque value here with no verification (R99).
		if rs.refreshToken != "" {
			return false, true, false
		}
		return false, false, true
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
