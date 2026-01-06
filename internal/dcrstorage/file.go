package dcrstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileStore implements Store using file-based storage.
// This is the default storage backend for backward compatibility with existing deployments.
// For distributed environments, consider using RedisStore instead.
type FileStore struct {
	basePath string
	logger   Logger
	mu       sync.RWMutex
}

// NewFileStore creates a new file-based credentials store.
// If basePath is empty, defaults to /tmp/oidc-client-credentials.json
func NewFileStore(basePath string, logger Logger) *FileStore {
	if basePath == "" {
		basePath = "/tmp/oidc-client-credentials.json"
	}
	if logger == nil {
		logger = NoOpLogger()
	}
	return &FileStore{
		basePath: basePath,
		logger:   logger,
	}
}

// BasePath returns the base path used for storing credentials
func (s *FileStore) BasePath() string {
	return s.basePath
}

// GetFilePath returns the file path for storing credentials for a specific provider.
// For multi-tenant scenarios, each provider gets a separate file based on URL hash.
func (s *FileStore) GetFilePath(providerURL string) string {
	if providerURL == "" {
		return s.basePath
	}

	// Hash provider URL for filename safety and uniqueness
	hash := sha256.Sum256([]byte(providerURL))
	hashStr := hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter filename

	ext := filepath.Ext(s.basePath)
	base := strings.TrimSuffix(s.basePath, ext)
	if ext == "" {
		ext = ".json"
	}

	return fmt.Sprintf("%s-%s%s", base, hashStr, ext)
}

// Save stores the client registration response to a file
func (s *FileStore) Save(ctx context.Context, providerURL string, creds *ClientRegistrationResponse) error {
	if creds == nil {
		return fmt.Errorf("credentials cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := s.GetFilePath(providerURL)

	// Ensure parent directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create credentials directory: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Write with restrictive permissions (owner read/write only)
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	s.logger.Debugf("Saved client credentials to %s", filePath)
	return nil
}

// Load retrieves stored credentials from a file.
// Returns nil, nil if no credentials file exists (not an error).
func (s *FileStore) Load(ctx context.Context, providerURL string) (*ClientRegistrationResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := s.GetFilePath(providerURL)

	// #nosec G304 -- path is constructed from trusted config values via GetFilePath()
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No credentials file exists - not an error
		}
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	var creds ClientRegistrationResponse
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %w", err)
	}

	s.logger.Debugf("Loaded client credentials from %s", filePath)
	return &creds, nil
}

// Delete removes the credentials file for a provider
func (s *FileStore) Delete(ctx context.Context, providerURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := s.GetFilePath(providerURL)

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to delete
		}
		return fmt.Errorf("failed to remove credentials file: %w", err)
	}

	s.logger.Debugf("Deleted client credentials from %s", filePath)
	return nil
}

// Exists checks if credentials exist for a provider
func (s *FileStore) Exists(ctx context.Context, providerURL string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := s.GetFilePath(providerURL)

	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check credentials file: %w", err)
	}

	return true, nil
}
