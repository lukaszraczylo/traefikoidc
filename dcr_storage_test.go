// Package traefikoidc provides OIDC authentication middleware for Traefik
package traefikoidc

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestFileCredentialsStore_SaveLoad tests the file-based credentials store
func TestFileCredentialsStore_SaveLoad(t *testing.T) {
	t.Parallel()

	// Create a temp directory for test files
	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")

	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	testCreds := &ClientRegistrationResponse{
		ClientID:                "test-client-id",
		ClientSecret:            "test-client-secret",
		ClientSecretExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
		RegistrationAccessToken: "test-access-token",
		RegistrationClientURI:   "https://example.com/register/test-client-id",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	ctx := context.Background()
	providerURL := "https://auth.example.com"

	t.Run("save and load credentials", func(t *testing.T) {
		// Save credentials
		err := store.Save(ctx, providerURL, testCreds)
		if err != nil {
			t.Fatalf("Failed to save credentials: %v", err)
		}

		// Load credentials
		loaded, err := store.Load(ctx, providerURL)
		if err != nil {
			t.Fatalf("Failed to load credentials: %v", err)
		}

		if loaded == nil {
			t.Fatal("Expected credentials but got nil")
		}

		// Verify fields
		if loaded.ClientID != testCreds.ClientID {
			t.Errorf("ClientID mismatch: got %s, want %s", loaded.ClientID, testCreds.ClientID)
		}
		if loaded.ClientSecret != testCreds.ClientSecret {
			t.Errorf("ClientSecret mismatch: got %s, want %s", loaded.ClientSecret, testCreds.ClientSecret)
		}
		if loaded.RegistrationAccessToken != testCreds.RegistrationAccessToken {
			t.Errorf("RegistrationAccessToken mismatch: got %s, want %s", loaded.RegistrationAccessToken, testCreds.RegistrationAccessToken)
		}
	})

	t.Run("load non-existent credentials", func(t *testing.T) {
		tempDir2 := t.TempDir()
		store2 := NewFileCredentialsStore(filepath.Join(tempDir2, "nonexistent.json"), logger)

		loaded, err := store2.Load(ctx, "https://nonexistent.example.com")
		if err != nil {
			t.Fatalf("Unexpected error for non-existent file: %v", err)
		}
		if loaded != nil {
			t.Error("Expected nil for non-existent credentials")
		}
	})

	t.Run("exists check", func(t *testing.T) {
		exists, err := store.Exists(ctx, providerURL)
		if err != nil {
			t.Fatalf("Exists check failed: %v", err)
		}
		if !exists {
			t.Error("Expected credentials to exist")
		}

		exists, err = store.Exists(ctx, "https://nonexistent.example.com")
		if err != nil {
			t.Fatalf("Exists check failed: %v", err)
		}
		if exists {
			t.Error("Expected credentials to not exist")
		}
	})

	t.Run("delete credentials", func(t *testing.T) {
		err := store.Delete(ctx, providerURL)
		if err != nil {
			t.Fatalf("Failed to delete credentials: %v", err)
		}

		exists, _ := store.Exists(ctx, providerURL)
		if exists {
			t.Error("Expected credentials to be deleted")
		}
	})

	t.Run("delete non-existent credentials", func(t *testing.T) {
		// Should not error
		err := store.Delete(ctx, "https://nonexistent.example.com")
		if err != nil {
			t.Fatalf("Delete should not error for non-existent: %v", err)
		}
	})
}

// TestFileCredentialsStore_MultiProvider tests multi-provider support
func TestFileCredentialsStore_MultiProvider(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	ctx := context.Background()

	provider1 := "https://auth1.example.com"
	provider2 := "https://auth2.example.com"

	creds1 := &ClientRegistrationResponse{
		ClientID:     "client-1",
		ClientSecret: "secret-1",
	}
	creds2 := &ClientRegistrationResponse{
		ClientID:     "client-2",
		ClientSecret: "secret-2",
	}

	// Save credentials for both providers
	if err := store.Save(ctx, provider1, creds1); err != nil {
		t.Fatalf("Failed to save creds1: %v", err)
	}
	if err := store.Save(ctx, provider2, creds2); err != nil {
		t.Fatalf("Failed to save creds2: %v", err)
	}

	// Load and verify each provider's credentials
	loaded1, err := store.Load(ctx, provider1)
	if err != nil {
		t.Fatalf("Failed to load creds1: %v", err)
	}
	if loaded1.ClientID != "client-1" {
		t.Errorf("Provider 1 ClientID mismatch: got %s", loaded1.ClientID)
	}

	loaded2, err := store.Load(ctx, provider2)
	if err != nil {
		t.Fatalf("Failed to load creds2: %v", err)
	}
	if loaded2.ClientID != "client-2" {
		t.Errorf("Provider 2 ClientID mismatch: got %s", loaded2.ClientID)
	}

	// Delete one shouldn't affect the other
	if err := store.Delete(ctx, provider1); err != nil {
		t.Fatalf("Failed to delete creds1: %v", err)
	}

	exists, _ := store.Exists(ctx, provider2)
	if !exists {
		t.Error("Provider 2 credentials should still exist")
	}
}

// TestFileCredentialsStore_ConcurrentAccess tests thread safety
func TestFileCredentialsStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	ctx := context.Background()
	providerURL := "https://auth.example.com"

	creds := &ClientRegistrationResponse{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	var wg sync.WaitGroup
	concurrency := 10

	// Concurrent saves
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Save(ctx, providerURL, creds)
		}()
	}
	wg.Wait()

	// Concurrent loads
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Load(ctx, providerURL)
		}()
	}
	wg.Wait()

	// Final verification
	loaded, err := store.Load(ctx, providerURL)
	if err != nil {
		t.Fatalf("Failed to load after concurrent access: %v", err)
	}
	if loaded == nil || loaded.ClientID != "test-client" {
		t.Error("Credentials corrupted after concurrent access")
	}
}

// TestFileCredentialsStore_InvalidInput tests error handling
func TestFileCredentialsStore_InvalidInput(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	ctx := context.Background()

	t.Run("save nil credentials", func(t *testing.T) {
		err := store.Save(ctx, "https://example.com", nil)
		if err == nil {
			t.Error("Expected error for nil credentials")
		}
	})

	t.Run("empty provider URL uses default path", func(t *testing.T) {
		creds := &ClientRegistrationResponse{ClientID: "test"}
		err := store.Save(ctx, "", creds)
		if err != nil {
			t.Fatalf("Save with empty provider URL failed: %v", err)
		}

		loaded, err := store.Load(ctx, "")
		if err != nil {
			t.Fatalf("Load with empty provider URL failed: %v", err)
		}
		if loaded == nil || loaded.ClientID != "test" {
			t.Error("Failed to load credentials with empty provider URL")
		}
	})
}

// TestFileCredentialsStore_DefaultPath tests default path behavior
func TestFileCredentialsStore_DefaultPath(t *testing.T) {
	t.Parallel()

	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore("", logger)

	// Just verify we can create with empty path and it has a default
	if store.basePath() == "" {
		t.Error("Expected default base path")
	}
}

// TestRedisCredentialsStore_WithMemoryCache tests Redis store with in-memory cache
func TestRedisCredentialsStore_WithMemoryCache(t *testing.T) {
	t.Parallel()

	// Create an in-memory cache for testing
	cache := NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeGeneral,
		MaxSize:    100,
		DefaultTTL: time.Hour,
		Logger:     GetSingletonNoOpLogger(),
	})
	defer cache.Close()

	logger := GetSingletonNoOpLogger()
	store := NewRedisCredentialsStore(cache, "", logger)

	ctx := context.Background()
	providerURL := "https://auth.example.com"

	testCreds := &ClientRegistrationResponse{
		ClientID:                "redis-test-client",
		ClientSecret:            "redis-test-secret",
		ClientSecretExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
		RegistrationAccessToken: "redis-test-token",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}

	t.Run("save and load credentials", func(t *testing.T) {
		err := store.Save(ctx, providerURL, testCreds)
		if err != nil {
			t.Fatalf("Failed to save credentials: %v", err)
		}

		loaded, err := store.Load(ctx, providerURL)
		if err != nil {
			t.Fatalf("Failed to load credentials: %v", err)
		}

		if loaded == nil {
			t.Fatal("Expected credentials but got nil")
		}
		if loaded.ClientID != testCreds.ClientID {
			t.Errorf("ClientID mismatch: got %s, want %s", loaded.ClientID, testCreds.ClientID)
		}
		if loaded.ClientSecret != testCreds.ClientSecret {
			t.Errorf("ClientSecret mismatch: got %s, want %s", loaded.ClientSecret, testCreds.ClientSecret)
		}
	})

	t.Run("exists check", func(t *testing.T) {
		exists, err := store.Exists(ctx, providerURL)
		if err != nil {
			t.Fatalf("Exists check failed: %v", err)
		}
		if !exists {
			t.Error("Expected credentials to exist")
		}
	})

	t.Run("delete credentials", func(t *testing.T) {
		err := store.Delete(ctx, providerURL)
		if err != nil {
			t.Fatalf("Failed to delete credentials: %v", err)
		}

		exists, _ := store.Exists(ctx, providerURL)
		if exists {
			t.Error("Expected credentials to be deleted")
		}
	})

	t.Run("load non-existent credentials", func(t *testing.T) {
		loaded, err := store.Load(ctx, "https://nonexistent.example.com")
		if err != nil {
			t.Fatalf("Unexpected error for non-existent: %v", err)
		}
		if loaded != nil {
			t.Error("Expected nil for non-existent credentials")
		}
	})
}

// TestRedisCredentialsStore_TTLFromExpiry tests TTL calculation
func TestRedisCredentialsStore_TTLFromExpiry(t *testing.T) {
	t.Parallel()

	cache := NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeGeneral,
		MaxSize:    100,
		DefaultTTL: time.Hour,
		Logger:     GetSingletonNoOpLogger(),
	})
	defer cache.Close()

	logger := GetSingletonNoOpLogger()
	store := NewRedisCredentialsStore(cache, "", logger)

	ctx := context.Background()

	t.Run("expired credentials should fail", func(t *testing.T) {
		expiredCreds := &ClientRegistrationResponse{
			ClientID:              "expired-client",
			ClientSecret:          "expired-secret",
			ClientSecretExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // Already expired
		}

		err := store.Save(ctx, "https://expired.example.com", expiredCreds)
		if err == nil {
			t.Error("Expected error for expired credentials")
		}
	})

	t.Run("credentials without expiry use default TTL", func(t *testing.T) {
		creds := &ClientRegistrationResponse{
			ClientID:              "no-expiry-client",
			ClientSecret:          "no-expiry-secret",
			ClientSecretExpiresAt: 0, // No expiry
		}

		err := store.Save(ctx, "https://noexpiry.example.com", creds)
		if err != nil {
			t.Fatalf("Failed to save credentials without expiry: %v", err)
		}
	})
}

// TestRedisCredentialsStore_InvalidInput tests error handling
func TestRedisCredentialsStore_InvalidInput(t *testing.T) {
	t.Parallel()

	cache := NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeGeneral,
		MaxSize:    100,
		DefaultTTL: time.Hour,
		Logger:     GetSingletonNoOpLogger(),
	})
	defer cache.Close()

	logger := GetSingletonNoOpLogger()
	store := NewRedisCredentialsStore(cache, "", logger)

	ctx := context.Background()

	t.Run("save nil credentials", func(t *testing.T) {
		err := store.Save(ctx, "https://example.com", nil)
		if err == nil {
			t.Error("Expected error for nil credentials")
		}
	})
}

// TestDCRStorageFactory tests the factory function
func TestDCRStorageFactory(t *testing.T) {
	t.Parallel()

	logger := GetSingletonNoOpLogger()

	t.Run("nil config returns error", func(t *testing.T) {
		_, err := NewDCRCredentialsStore(nil, nil, logger)
		if err == nil {
			t.Error("Expected error for nil config")
		}
	})

	t.Run("file backend creates file store", func(t *testing.T) {
		config := &DynamicClientRegistrationConfig{
			Enabled:            true,
			PersistCredentials: true,
			StorageBackend:     "file",
			CredentialsFile:    "/tmp/test-creds.json",
		}

		store, err := NewDCRCredentialsStore(config, nil, logger)
		if err != nil {
			t.Fatalf("Failed to create file store: %v", err)
		}
		if store == nil {
			t.Error("Expected store but got nil")
		}

		_, ok := store.(*FileCredentialsStore)
		if !ok {
			t.Error("Expected FileCredentialsStore")
		}
	})

	t.Run("redis backend without cache manager returns error", func(t *testing.T) {
		config := &DynamicClientRegistrationConfig{
			Enabled:            true,
			PersistCredentials: true,
			StorageBackend:     "redis",
		}

		_, err := NewDCRCredentialsStore(config, nil, logger)
		if err == nil {
			t.Error("Expected error for redis backend without cache manager")
		}
	})

	t.Run("auto backend without redis falls back to file", func(t *testing.T) {
		config := &DynamicClientRegistrationConfig{
			Enabled:            true,
			PersistCredentials: true,
			StorageBackend:     "auto",
		}

		store, err := NewDCRCredentialsStore(config, nil, logger)
		if err != nil {
			t.Fatalf("Failed to create auto store: %v", err)
		}

		_, ok := store.(*FileCredentialsStore)
		if !ok {
			t.Error("Expected FileCredentialsStore for auto without redis")
		}
	})

	t.Run("unknown backend returns error", func(t *testing.T) {
		config := &DynamicClientRegistrationConfig{
			Enabled:            true,
			PersistCredentials: true,
			StorageBackend:     "unknown",
		}

		_, err := NewDCRCredentialsStore(config, nil, logger)
		if err == nil {
			t.Error("Expected error for unknown backend")
		}
	})

	t.Run("empty backend defaults to auto", func(t *testing.T) {
		config := &DynamicClientRegistrationConfig{
			Enabled:            true,
			PersistCredentials: true,
			StorageBackend:     "",
		}

		store, err := NewDCRCredentialsStore(config, nil, logger)
		if err != nil {
			t.Fatalf("Failed to create store with empty backend: %v", err)
		}

		// Should default to file (auto without redis)
		_, ok := store.(*FileCredentialsStore)
		if !ok {
			t.Error("Expected FileCredentialsStore for empty backend")
		}
	})
}

// TestDynamicClientRegistrar_WithStore tests registrar with store
func TestDynamicClientRegistrar_WithStore(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	config := &DynamicClientRegistrationConfig{
		Enabled:            true,
		PersistCredentials: true,
	}

	registrar := NewDynamicClientRegistrarWithStore(
		nil, // httpClient
		logger,
		config,
		"https://auth.example.com",
		store,
	)

	if registrar == nil {
		t.Fatal("Expected registrar but got nil")
	}

	if registrar.store == nil {
		t.Error("Expected store to be set")
	}

	// Test SetStore
	newStore := NewFileCredentialsStore(filepath.Join(tempDir, "new.json"), logger)
	registrar.SetStore(newStore)

	if registrar.store != newStore {
		t.Error("SetStore did not update the store")
	}
}

// TestDynamicClientRegistrar_CredentialsFromStore tests loading from store
func TestDynamicClientRegistrar_CredentialsFromStore(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	providerURL := "https://auth.example.com"
	ctx := context.Background()

	// Pre-save credentials
	testCreds := &ClientRegistrationResponse{
		ClientID:              "pre-saved-client",
		ClientSecret:          "pre-saved-secret",
		ClientSecretExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	if err := store.Save(ctx, providerURL, testCreds); err != nil {
		t.Fatalf("Failed to pre-save credentials: %v", err)
	}

	config := &DynamicClientRegistrationConfig{
		Enabled:            true,
		PersistCredentials: true,
	}

	registrar := NewDynamicClientRegistrarWithStore(
		nil,
		logger,
		config,
		providerURL,
		store,
	)

	// Test loading via the internal method
	loaded, err := registrar.loadCredentialsFromStore(ctx)
	if err != nil {
		t.Fatalf("Failed to load from store: %v", err)
	}
	if loaded == nil {
		t.Fatal("Expected credentials but got nil")
	}
	if loaded.ClientID != "pre-saved-client" {
		t.Errorf("ClientID mismatch: got %s", loaded.ClientID)
	}
}

// TestFileCredentialsStore_CorruptedFile tests handling of corrupted files
func TestFileCredentialsStore_CorruptedFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(basePath, logger)

	ctx := context.Background()
	providerURL := "https://auth.example.com"

	// Write corrupted JSON
	filePath := store.getFilePath(providerURL)
	if err := os.WriteFile(filePath, []byte("{corrupted json"), 0600); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Should return error for corrupted file
	_, err := store.Load(ctx, providerURL)
	if err == nil {
		t.Error("Expected error for corrupted JSON")
	}
}

// TestFileCredentialsStore_DirectoryCreation tests auto directory creation
func TestFileCredentialsStore_DirectoryCreation(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	deepPath := filepath.Join(tempDir, "deep", "nested", "path", "credentials.json")
	logger := GetSingletonNoOpLogger()
	store := NewFileCredentialsStore(deepPath, logger)

	ctx := context.Background()
	creds := &ClientRegistrationResponse{ClientID: "test"}

	err := store.Save(ctx, "https://example.com", creds)
	if err != nil {
		t.Fatalf("Failed to save with nested directory: %v", err)
	}

	loaded, err := store.Load(ctx, "https://example.com")
	if err != nil {
		t.Fatalf("Failed to load after nested directory creation: %v", err)
	}
	if loaded == nil || loaded.ClientID != "test" {
		t.Error("Failed to load credentials from nested directory")
	}
}
