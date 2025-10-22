package traefikoidc

import (
	"encoding/json"
)

// REDACTED is the placeholder value for sensitive information
const REDACTED = "[REDACTED]"

// MarshalJSON implements custom JSON marshalling to redact sensitive fields
// Rewritten without type aliases for yaegi compatibility
func (c Config) MarshalJSON() ([]byte, error) {
	// Build a map manually to avoid type alias issues with yaegi
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

	// Redact sensitive fields
	result["clientSecret"] = REDACTED
	result["sessionEncryptionKey"] = REDACTED

	// Handle Redis config
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

	return json.Marshal(result)
}

// MarshalYAML implements custom YAML marshalling to redact sensitive fields
// Rewritten without type aliases for yaegi compatibility
func (c Config) MarshalYAML() (interface{}, error) {
	// Build a map manually to avoid type alias issues with yaegi
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

	// Redact sensitive fields
	result["clientSecret"] = REDACTED
	result["sessionEncryptionKey"] = REDACTED

	// Handle Redis config
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

	return result, nil
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
