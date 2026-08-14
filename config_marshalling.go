package traefikoidc

import (
	"encoding/json"
)

// REDACTED is the placeholder value for sensitive information
const REDACTED = "[REDACTED]"

// marshalDCR builds the JSON/YAML-safe representation of the dynamic
// client registration config, redacting the initial access token.
func marshalDCR(d *DynamicClientRegistrationConfig) map[string]interface{} {
	if d == nil {
		return nil
	}
	m := make(map[string]interface{})
	m["enabled"] = d.Enabled
	m["persistCredentials"] = d.PersistCredentials
	m["storageBackend"] = d.StorageBackend
	m["initialAccessToken"] = REDACTED
	m["registrationEndpoint"] = d.RegistrationEndpoint
	m["credentialsFile"] = d.CredentialsFile
	m["redisKeyPrefix"] = d.RedisKeyPrefix
	return m
}

// configToMap builds the JSON/YAML-safe map representation of Config. Both
// MarshalJSON and MarshalYAML share it so the (hand-maintained for yaegi
// compatibility) field/redaction list cannot drift between the two
// encoders — previously the list silently dropped entire config areas
// (dynamicClientRegistration, securityHeaders, audience, overrideScopes,
// enablePKCE, allowOpaqueTokens, requireTokenIntrospection,
// strictAudienceValidation, extraAuthParams, client assertion settings)
// and never redacted their embedded secrets (R150).
func (c Config) configToMap() map[string]interface{} {
	result := make(map[string]interface{})

	// Copy public fields
	result["providerURL"] = c.ProviderURL
	result["clientID"] = c.ClientID
	result["callbackURL"] = c.CallbackURL
	result["logoutURL"] = c.LogoutURL
	result["postLogoutRedirectURI"] = c.PostLogoutRedirectURI
	result["scopes"] = c.Scopes
	result["forceHTTPS"] = c.ForceHTTPS
	result["logLevel"] = c.LogLevel
	result["rateLimit"] = c.RateLimit
	result["excludedURLs"] = c.ExcludedURLs
	result["allowedUserDomains"] = c.AllowedUserDomains
	result["allowedUsers"] = c.AllowedUsers
	result["allowedRolesAndGroups"] = c.AllowedRolesAndGroups

	// Fields that the legacy hand-written list dropped (R150): important
	// non-secret config that must survive any JSON/YAML round-trip.
	result["audience"] = c.Audience
	result["cookiePrefix"] = c.CookiePrefix
	result["cookieDomain"] = c.CookieDomain
	result["userIdentifierClaim"] = c.UserIdentifierClaim
	result["groupClaimName"] = c.GroupClaimName
	result["roleClaimName"] = c.RoleClaimName
	result["oidcEndSessionURL"] = c.OIDCEndSessionURL
	result["revocationURL"] = c.RevocationURL
	result["introspectionURL"] = c.IntrospectionURL
	result["headers"] = c.Headers
	result["allowedClaims"] = c.AllowedClaims
	result["extraAuthParams"] = c.ExtraAuthParams
	result["refreshGracePeriodSeconds"] = c.RefreshGracePeriodSeconds
	result["maxRefreshTokenAgeSeconds"] = c.MaxRefreshTokenAgeSeconds
	result["sessionMaxAge"] = c.SessionMaxAge
	result["overrideScopes"] = c.OverrideScopes
	result["disableReplayDetection"] = c.DisableReplayDetection
	result["requireTokenIntrospection"] = c.RequireTokenIntrospection
	result["allowOpaqueTokens"] = c.AllowOpaqueTokens
	result["strictAudienceValidation"] = c.StrictAudienceValidation
	result["enablePKCE"] = c.EnablePKCE
	result["allowPrivateIPAddresses"] = c.AllowPrivateIPAddresses
	result["minimalHeaders"] = c.MinimalHeaders
	result["stripAuthCookies"] = c.StripAuthCookies
	result["enableBackchannelLogout"] = c.EnableBackchannelLogout
	result["enableFrontchannelLogout"] = c.EnableFrontchannelLogout
	result["backchannelLogoutURL"] = c.BackchannelLogoutURL
	result["frontchannelLogoutURL"] = c.FrontchannelLogoutURL
	result["caCertPath"] = c.CACertPath
	result["caCertPEM"] = c.CACertPEM
	result["insecureSkipVerify"] = c.InsecureSkipVerify
	result["clientAuthMethod"] = c.ClientAuthMethod
	result["clientAssertionKeyID"] = c.ClientAssertionKeyID
	result["clientAssertionAlg"] = c.ClientAssertionAlg
	result["enableBearerAuth"] = c.EnableBearerAuth
	result["bearerIdentifierClaim"] = c.BearerIdentifierClaim
	result["stripAuthorizationHeader"] = c.StripAuthorizationHeader
	result["bearerEmitWWWAuthenticate"] = c.BearerEmitWWWAuthenticate
	result["bearerOverridesCookie"] = c.BearerOverridesCookie
	result["maxTokenAgeSeconds"] = c.MaxTokenAgeSeconds
	result["maxIdentifierLength"] = c.MaxIdentifierLength
	result["bearerFailureThreshold"] = c.BearerFailureThreshold
	result["bearerFailureWindowSeconds"] = c.BearerFailureWindowSeconds
	result["bearerFailurePenaltySeconds"] = c.BearerFailurePenaltySeconds

	// Redact sensitive fields (existing secrets plus the previously-leaked
	// client assertion private key, R150).
	result["clientSecret"] = REDACTED
	result["sessionEncryptionKey"] = REDACTED
	result["clientAssertionPrivateKey"] = REDACTED

	// Handle Redis config (redacts password)
	if c.Redis != nil {
		redisMap := make(map[string]interface{})
		redisMap["enabled"] = c.Redis.Enabled
		redisMap["address"] = c.Redis.Address
		redisMap["password"] = REDACTED
		redisMap["db"] = c.Redis.DB
		redisMap["poolSize"] = c.Redis.PoolSize
		redisMap["cacheMode"] = c.Redis.CacheMode
		result["redis"] = redisMap
	}

	// Handle dynamic client registration (redacts the initial access token)
	if c.DynamicClientRegistration != nil {
		result["dynamicClientRegistration"] = marshalDCR(c.DynamicClientRegistration)
	}

	// Handle security headers
	if c.SecurityHeaders != nil {
		result["securityHeaders"] = c.SecurityHeaders
	}

	return result
}

// MarshalJSON implements custom JSON marshaling to redact sensitive fields
// Rewritten without type aliases for yaegi compatibility
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.configToMap())
}

// MarshalYAML implements custom YAML marshaling to redact sensitive fields
// Rewritten without type aliases for yaegi compatibility
func (c Config) MarshalYAML() (interface{}, error) {
	return c.configToMap(), nil
}

// MarshalJSON for RedisConfig to redact sensitive fields
// Rewritten without type aliases for yaegi compatibility
func (r RedisConfig) MarshalJSON() ([]byte, error) {
	result := make(map[string]interface{})
	result["enabled"] = r.Enabled
	result["address"] = r.Address
	result["password"] = REDACTED
	result["db"] = r.DB
	result["poolSize"] = r.PoolSize
	result["cacheMode"] = r.CacheMode

	return json.Marshal(result)
}

// MarshalYAML for RedisConfig to redact sensitive fields
// Rewritten without type aliases for yaegi compatibility
func (r RedisConfig) MarshalYAML() (interface{}, error) {
	result := make(map[string]interface{})
	result["enabled"] = r.Enabled
	result["address"] = r.Address
	result["password"] = REDACTED
	result["db"] = r.DB
	result["poolSize"] = r.PoolSize
	result["cacheMode"] = r.CacheMode

	return result, nil
}
