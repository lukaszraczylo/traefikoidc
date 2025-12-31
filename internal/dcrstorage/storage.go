// Package dcrstorage provides storage backends for OIDC Dynamic Client Registration credentials.
// It supports both file-based and Redis-based storage for persisting client credentials
// across application restarts and distributed deployments.
package dcrstorage

import (
	"context"
)

// StorageBackend represents the type of storage backend for DCR credentials
type StorageBackend string

const (
	// StorageBackendFile uses file-based storage (default for backward compatibility)
	StorageBackendFile StorageBackend = "file"

	// StorageBackendRedis uses Redis for distributed storage
	StorageBackendRedis StorageBackend = "redis"

	// StorageBackendAuto automatically selects Redis if available, otherwise file
	StorageBackendAuto StorageBackend = "auto"
)

// Logger interface for DCR storage operations
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...any)
	Info(msg string)
	Infof(format string, args ...any)
	Error(msg string)
	Errorf(format string, args ...any)
}

// ClientRegistrationResponse represents the response from a successful client registration (RFC 7591)
type ClientRegistrationResponse struct {
	SubjectType             string   `json:"subject_type,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
}

// Store defines the interface for storing DCR credentials.
// This abstraction allows different storage backends (file, Redis) to be used
// for persisting OIDC Dynamic Client Registration credentials across nodes.
type Store interface {
	// Save stores the client registration response for a provider
	// The providerURL is used as a key to support multi-tenant scenarios
	Save(ctx context.Context, providerURL string, creds *ClientRegistrationResponse) error

	// Load retrieves stored credentials for a provider
	// Returns nil, nil if no credentials exist (not an error)
	Load(ctx context.Context, providerURL string) (*ClientRegistrationResponse, error)

	// Delete removes stored credentials for a provider
	Delete(ctx context.Context, providerURL string) error

	// Exists checks if credentials exist for a provider
	Exists(ctx context.Context, providerURL string) (bool, error)
}

// noOpLogger is a no-op implementation of Logger for default use
type noOpLogger struct{}

func (n noOpLogger) Debug(msg string)                  {}
func (n noOpLogger) Debugf(format string, args ...any) {}
func (n noOpLogger) Info(msg string)                   {}
func (n noOpLogger) Infof(format string, args ...any)  {}
func (n noOpLogger) Error(msg string)                  {}
func (n noOpLogger) Errorf(format string, args ...any) {}

// NoOpLogger returns a no-op logger instance
func NoOpLogger() Logger {
	return noOpLogger{}
}
