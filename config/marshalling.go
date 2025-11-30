// Package config provides unified configuration management for the OIDC middleware
package config

import (
	"encoding/json"
)

// REDACTED is the placeholder value for sensitive information
const REDACTED = "[REDACTED]"

// MarshalJSON implements custom JSON marshalling to redact sensitive fields
func (c UnifiedConfig) MarshalJSON() ([]byte, error) {
	// Create an alias to avoid recursion
	type Alias UnifiedConfig

	// Create a copy with redacted sensitive fields
	copy := (Alias)(c)

	// Redact provider secrets
	if copy.Provider.ClientSecret != "" {
		copy.Provider.ClientSecret = REDACTED
	}

	// Redact session secrets
	if copy.Session.Secret != "" {
		copy.Session.Secret = REDACTED
	}
	if copy.Session.EncryptionKey != "" {
		copy.Session.EncryptionKey = REDACTED
	}
	if copy.Session.SigningKey != "" {
		copy.Session.SigningKey = REDACTED
	}

	// Redact Redis passwords
	if copy.Redis.Password != "" {
		copy.Redis.Password = REDACTED
	}
	if copy.Redis.SentinelPassword != "" {
		copy.Redis.SentinelPassword = REDACTED
	}

	return json.Marshal(copy)
}

// MarshalJSON for ProviderConfig to redact sensitive fields
func (p ProviderConfig) MarshalJSON() ([]byte, error) {
	type Alias ProviderConfig
	copy := (Alias)(p)

	if copy.ClientSecret != "" {
		copy.ClientSecret = REDACTED
	}

	return json.Marshal(copy)
}

// MarshalJSON for SessionConfig to redact sensitive fields
func (s SessionConfig) MarshalJSON() ([]byte, error) {
	type Alias SessionConfig
	copy := (Alias)(s)

	if copy.Secret != "" {
		copy.Secret = REDACTED
	}
	if copy.EncryptionKey != "" {
		copy.EncryptionKey = REDACTED
	}
	if copy.SigningKey != "" {
		copy.SigningKey = REDACTED
	}

	return json.Marshal(copy)
}

// MarshalJSON for RedisConfig to redact sensitive fields
func (r RedisConfig) MarshalJSON() ([]byte, error) {
	type Alias RedisConfig
	copy := (Alias)(r)

	if copy.Password != "" {
		copy.Password = REDACTED
	}
	if copy.SentinelPassword != "" {
		copy.SentinelPassword = REDACTED
	}

	return json.Marshal(copy)
}

// MarshalYAML implements custom YAML marshalling to redact sensitive fields
func (c UnifiedConfig) MarshalYAML() (interface{}, error) {
	// Create an alias to avoid recursion
	type Alias UnifiedConfig

	// Create a copy with redacted sensitive fields
	copy := (Alias)(c)

	// Redact provider secrets
	if copy.Provider.ClientSecret != "" {
		copy.Provider.ClientSecret = REDACTED
	}

	// Redact session secrets
	if copy.Session.Secret != "" {
		copy.Session.Secret = REDACTED
	}
	if copy.Session.EncryptionKey != "" {
		copy.Session.EncryptionKey = REDACTED
	}
	if copy.Session.SigningKey != "" {
		copy.Session.SigningKey = REDACTED
	}

	// Redact Redis passwords
	if copy.Redis.Password != "" {
		copy.Redis.Password = REDACTED
	}
	if copy.Redis.SentinelPassword != "" {
		copy.Redis.SentinelPassword = REDACTED
	}

	return copy, nil
}

// MarshalYAML for ProviderConfig to redact sensitive fields
func (p ProviderConfig) MarshalYAML() (interface{}, error) {
	type Alias ProviderConfig
	copy := (Alias)(p)

	if copy.ClientSecret != "" {
		copy.ClientSecret = REDACTED
	}

	return copy, nil
}

// MarshalYAML for SessionConfig to redact sensitive fields
func (s SessionConfig) MarshalYAML() (interface{}, error) {
	type Alias SessionConfig
	copy := (Alias)(s)

	if copy.Secret != "" {
		copy.Secret = REDACTED
	}
	if copy.EncryptionKey != "" {
		copy.EncryptionKey = REDACTED
	}
	if copy.SigningKey != "" {
		copy.SigningKey = REDACTED
	}

	return copy, nil
}

// MarshalYAML for RedisConfig to redact sensitive fields
func (r RedisConfig) MarshalYAML() (interface{}, error) {
	type Alias RedisConfig
	copy := (Alias)(r)

	if copy.Password != "" {
		copy.Password = REDACTED
	}
	if copy.SentinelPassword != "" {
		copy.SentinelPassword = REDACTED
	}

	return copy, nil
}
