package dcrstorage

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mockCache implements Cache for testing
type mockCache struct {
	data map[string]cacheEntry
	mu   sync.RWMutex
}

type cacheEntry struct {
	value     any
	expiresAt time.Time
}

func newMockCache() *mockCache {
	return &mockCache{data: make(map[string]cacheEntry)}
}

func (m *mockCache) Get(key string) (any, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

func (m *mockCache) Set(key string, value any, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (m *mockCache) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

func TestFileStore_SaveLoad(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")

	store := NewFileStore(basePath, nil)

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
		if loaded.RegistrationAccessToken != testCreds.RegistrationAccessToken {
			t.Errorf("RegistrationAccessToken mismatch: got %s, want %s", loaded.RegistrationAccessToken, testCreds.RegistrationAccessToken)
		}
	})

	t.Run("load non-existent credentials", func(t *testing.T) {
		tempDir2 := t.TempDir()
		store2 := NewFileStore(filepath.Join(tempDir2, "nonexistent.json"), nil)

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
		err := store.Delete(ctx, "https://nonexistent.example.com")
		if err != nil {
			t.Fatalf("Delete should not error for non-existent: %v", err)
		}
	})
}

func TestFileStore_MultiProvider(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	store := NewFileStore(basePath, nil)

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

	if err := store.Save(ctx, provider1, creds1); err != nil {
		t.Fatalf("Failed to save creds1: %v", err)
	}
	if err := store.Save(ctx, provider2, creds2); err != nil {
		t.Fatalf("Failed to save creds2: %v", err)
	}

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

	if err := store.Delete(ctx, provider1); err != nil {
		t.Fatalf("Failed to delete creds1: %v", err)
	}

	exists, _ := store.Exists(ctx, provider2)
	if !exists {
		t.Error("Provider 2 credentials should still exist")
	}
}

func TestFileStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	store := NewFileStore(basePath, nil)

	ctx := context.Background()
	providerURL := "https://auth.example.com"

	creds := &ClientRegistrationResponse{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	var wg sync.WaitGroup
	concurrency := 10

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Save(ctx, providerURL, creds)
		}()
	}
	wg.Wait()

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Load(ctx, providerURL)
		}()
	}
	wg.Wait()

	loaded, err := store.Load(ctx, providerURL)
	if err != nil {
		t.Fatalf("Failed to load after concurrent access: %v", err)
	}
	if loaded == nil || loaded.ClientID != "test-client" {
		t.Error("Credentials corrupted after concurrent access")
	}
}

func TestFileStore_InvalidInput(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	store := NewFileStore(basePath, nil)

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

func TestFileStore_DefaultPath(t *testing.T) {
	t.Parallel()

	store := NewFileStore("", nil)

	if store.BasePath() == "" {
		t.Error("Expected default base path")
	}
}

func TestRedisStore_WithMockCache(t *testing.T) {
	t.Parallel()

	cache := newMockCache()
	store := NewRedisStore(cache, "", nil)

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

func TestRedisStore_TTLFromExpiry(t *testing.T) {
	t.Parallel()

	cache := newMockCache()
	store := NewRedisStore(cache, "", nil)

	ctx := context.Background()

	t.Run("expired credentials should fail", func(t *testing.T) {
		expiredCreds := &ClientRegistrationResponse{
			ClientID:              "expired-client",
			ClientSecret:          "expired-secret",
			ClientSecretExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
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
			ClientSecretExpiresAt: 0,
		}

		err := store.Save(ctx, "https://noexpiry.example.com", creds)
		if err != nil {
			t.Fatalf("Failed to save credentials without expiry: %v", err)
		}
	})
}

func TestRedisStore_InvalidInput(t *testing.T) {
	t.Parallel()

	cache := newMockCache()
	store := NewRedisStore(cache, "", nil)

	ctx := context.Background()

	t.Run("save nil credentials", func(t *testing.T) {
		err := store.Save(ctx, "https://example.com", nil)
		if err == nil {
			t.Error("Expected error for nil credentials")
		}
	})
}

func TestFileStore_CorruptedFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "credentials.json")
	store := NewFileStore(basePath, nil)

	ctx := context.Background()
	providerURL := "https://auth.example.com"

	filePath := store.GetFilePath(providerURL)
	if err := os.WriteFile(filePath, []byte("{corrupted json"), 0600); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	_, err := store.Load(ctx, providerURL)
	if err == nil {
		t.Error("Expected error for corrupted JSON")
	}
}

func TestFileStore_DirectoryCreation(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	deepPath := filepath.Join(tempDir, "deep", "nested", "path", "credentials.json")
	store := NewFileStore(deepPath, nil)

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
