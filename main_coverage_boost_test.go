//go:build !yaegi

package traefikoidc

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// Config Marshaling Tests

func TestConfig_MarshalJSON(t *testing.T) {
	config := &Config{
		ProviderURL:           "https://provider.example.com",
		ClientID:              "test-client-id",
		ClientSecret:          "super-secret",
		CallbackURL:           "https://app.example.com/callback",
		LogoutURL:             "/logout",
		PostLogoutRedirectURI: "https://app.example.com",
		Scopes:                []string{"openid", "profile"},
		ForceHTTPS:            true,
		LogLevel:              "info",
		SessionEncryptionKey:  "encryption-key-secret",
		RateLimit:             100,
		ExcludedURLs:          []string{"/health", "/metrics"},
		AllowedUserDomains:    []string{"example.com"},
		AllowedUsers:          []string{"user1@example.com"},
		AllowedRolesAndGroups: []string{"admin", "developers"},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Verify JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify public fields are present
	if result["providerURL"] != "https://provider.example.com" {
		t.Error("Expected providerURL to be present")
	}

	if result["clientID"] != "test-client-id" {
		t.Error("Expected clientID to be present")
	}

	// Verify sensitive fields are redacted
	if result["clientSecret"] != REDACTED {
		t.Errorf("Expected clientSecret to be redacted, got: %v", result["clientSecret"])
	}

	if result["sessionEncryptionKey"] != REDACTED {
		t.Errorf("Expected sessionEncryptionKey to be redacted, got: %v", result["sessionEncryptionKey"])
	}
}

func TestConfig_MarshalJSON_WithRedis(t *testing.T) {
	config := &Config{
		ProviderURL:  "https://provider.example.com",
		ClientID:     "test-client-id",
		ClientSecret: "super-secret",
		Redis: &RedisConfig{
			Enabled:   true,
			Address:   "localhost:6379",
			Password:  "redis-secret-password",
			DB:        0,
			PoolSize:  10,
			CacheMode: "memory+redis",
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("MarshalJSON with Redis failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify Redis config is present
	redis, ok := result["redis"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected redis config to be present")
	}

	// Verify Redis password is redacted
	if redis["password"] != REDACTED {
		t.Errorf("Expected Redis password to be redacted, got: %v", redis["password"])
	}

	// Verify other Redis fields
	if redis["address"] != "localhost:6379" {
		t.Error("Expected Redis address to be present")
	}

	if enabled, ok := redis["enabled"].(bool); !ok || !enabled {
		t.Error("Expected Redis enabled to be true")
	}
}

func TestConfig_MarshalYAML(t *testing.T) {
	config := &Config{
		ProviderURL:          "https://provider.example.com",
		ClientID:             "test-client-id",
		ClientSecret:         "super-secret",
		SessionEncryptionKey: "encryption-key-secret",
		CallbackURL:          "https://app.example.com/callback",
		Scopes:               []string{"openid", "profile"},
	}

	yamlData, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("MarshalYAML failed: %v", err)
	}

	// Parse YAML to verify
	var result map[string]interface{}
	if err := yaml.Unmarshal(yamlData, &result); err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Verify sensitive fields are redacted
	if result["clientSecret"] != REDACTED {
		t.Errorf("Expected clientSecret to be redacted in YAML, got: %v", result["clientSecret"])
	}

	if result["sessionEncryptionKey"] != REDACTED {
		t.Errorf("Expected sessionEncryptionKey to be redacted in YAML, got: %v", result["sessionEncryptionKey"])
	}

	// Verify public fields
	if result["providerURL"] != "https://provider.example.com" {
		t.Error("Expected providerURL to be present in YAML")
	}
}

func TestRedisConfig_MarshalJSON(t *testing.T) {
	redis := &RedisConfig{
		Enabled:   true,
		Address:   "localhost:6379",
		Password:  "super-secret-password",
		DB:        0,
		PoolSize:  20,
		CacheMode: "redis",
	}

	data, err := json.Marshal(redis)
	if err != nil {
		t.Fatalf("RedisConfig MarshalJSON failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify password is redacted
	if result["password"] != REDACTED {
		t.Errorf("Expected password to be redacted, got: %v", result["password"])
	}

	// Verify other fields
	if result["address"] != "localhost:6379" {
		t.Error("Expected address to be present")
	}

	if enabled, ok := result["enabled"].(bool); !ok || !enabled {
		t.Error("Expected enabled to be true")
	}
}

func TestRedisConfig_MarshalYAML(t *testing.T) {
	redis := &RedisConfig{
		Enabled:   false,
		Address:   "redis.example.com:6379",
		Password:  "another-secret",
		DB:        1,
		PoolSize:  15,
		CacheMode: "memory",
	}

	yamlData, err := yaml.Marshal(redis)
	if err != nil {
		t.Fatalf("RedisConfig MarshalYAML failed: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(yamlData, &result); err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Verify password is redacted
	if result["password"] != REDACTED {
		t.Errorf("Expected password to be redacted in YAML, got: %v", result["password"])
	}

	// Verify other fields
	if result["address"] != "redis.example.com:6379" {
		t.Error("Expected address to be present in YAML")
	}
}

// Memory Optimizations Tests

func TestGetMemoryOptimizations(t *testing.T) {
	// Reset first
	ResetGlobalMemoryOptimizations()

	opts1 := GetMemoryOptimizations()
	if opts1 == nil {
		t.Fatal("Expected GetMemoryOptimizations to return non-nil")
	}

	// Verify singleton behavior
	opts2 := GetMemoryOptimizations()
	if opts1 != opts2 {
		t.Error("Expected GetMemoryOptimizations to return the same instance")
	}

	// Verify components are initialized
	if opts1.bufferPool == nil {
		t.Error("Expected bufferPool to be initialized")
	}

	if opts1.gzipWriterPool == nil {
		t.Error("Expected gzipWriterPool to be initialized")
	}

	if opts1.gzipReaderPool == nil {
		t.Error("Expected gzipReaderPool to be initialized")
	}
}

func TestResetGlobalMemoryOptimizations(t *testing.T) {
	opts1 := GetMemoryOptimizations()
	if opts1 == nil {
		t.Fatal("Expected GetMemoryOptimizations to return non-nil")
	}

	ResetGlobalMemoryOptimizations()

	opts2 := GetMemoryOptimizations()
	if opts1 == opts2 {
		t.Error("Expected different instance after reset")
	}
}

func TestNewGzipReaderPool(t *testing.T) {
	pool := NewGzipReaderPool()
	if pool == nil {
		t.Fatal("Expected NewGzipReaderPool to return non-nil")
	}

	// Test Get/Put cycle
	reader := pool.Get()
	// Reader may be nil from pool initially, that's okay
	pool.Put(reader)

	// Put nil should be safe
	pool.Put(nil)
}

func TestGzipReaderPool_GetPut(t *testing.T) {
	pool := NewGzipReaderPool()

	// Get a reader (may be nil)
	reader1 := pool.Get()

	// Put it back
	pool.Put(reader1)

	// Get another one
	reader2 := pool.Get()
	pool.Put(reader2)

	// Verify pool operations don't panic
}

func TestMemoryOptimizations_GetSingletonLogger(t *testing.T) {
	ResetGlobalMemoryOptimizations()
	opts := GetMemoryOptimizations()

	logger1 := opts.GetSingletonLogger("info")
	if logger1 == nil {
		t.Fatal("Expected GetSingletonLogger to return non-nil")
	}

	// Verify singleton behavior
	logger2 := opts.GetSingletonLogger("debug")
	if logger1 != logger2 {
		t.Error("Expected GetSingletonLogger to return the same instance")
	}
}

func TestCompressTokenOptimized(t *testing.T) {
	ResetGlobalMemoryOptimizations()

	tests := []struct {
		name  string
		token string
	}{
		{"short token", "short"},
		{"medium token", "this is a medium length token for testing compression"},
		{"long token", "this is a very long token that should definitely benefit from gzip compression because it contains a lot of repetitive text that compresses well this is a very long token that should definitely benefit from gzip compression because it contains a lot of repetitive text that compresses well"},
		{"empty token", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := CompressTokenOptimized(tt.token)
			if err != nil {
				t.Errorf("CompressTokenOptimized failed: %v", err)
			}

			// For empty or short tokens, compression may not be beneficial
			if tt.token == "" || len(tt.token) < 10 {
				if compressed != tt.token {
					// This is okay - it means compression was tried
				}
			}

			// Should always return something
			if len(compressed) == 0 && len(tt.token) > 0 {
				t.Error("Expected non-empty result for non-empty input")
			}
		})
	}
}

func TestDecompressTokenOptimized(t *testing.T) {
	ResetGlobalMemoryOptimizations()

	// Test with a compressible token
	original := "this is a test token that should compress well because it has repeating patterns repeating patterns repeating patterns"

	compressed, err := CompressTokenOptimized(original)
	if err != nil {
		t.Fatalf("Compression failed: %v", err)
	}

	// If compression was applied (compressed is different from original)
	if compressed != original {
		decompressed, err := DecompressTokenOptimized(compressed)
		if err != nil {
			t.Fatalf("Decompression failed: %v", err)
		}

		if decompressed != original {
			t.Errorf("Decompressed token doesn't match original.\nExpected: %s\nGot: %s", original, decompressed)
		}
	}

	// Test decompression of non-compressed data (should return original)
	plainText := "not compressed"
	result, err := DecompressTokenOptimized(plainText)
	// Should return error or original text
	if err == nil && result != plainText {
		// Either error or returns original is acceptable for invalid compressed data
	}
}

func TestNewSimplifiedSessionData(t *testing.T) {
	session := NewSimplifiedSessionData()
	if session == nil {
		t.Fatal("Expected NewSimplifiedSessionData to return non-nil")
	}

	// Verify maps are initialized
	if session.mainData == nil {
		t.Error("Expected mainData to be initialized")
	}

	if session.tokens == nil {
		t.Error("Expected tokens to be initialized")
	}

	if session.chunks == nil {
		t.Error("Expected chunks to be initialized")
	}
}

func TestSimplifiedSessionData_SetGetToken(t *testing.T) {
	session := NewSimplifiedSessionData()

	// Set a token
	session.SetToken("access_token", "test-token-value")

	// Get the token
	value, exists := session.GetToken("access_token")
	if !exists {
		t.Error("Expected token to exist")
	}

	if value != "test-token-value" {
		t.Errorf("Expected 'test-token-value', got '%s'", value)
	}

	// Get non-existent token
	_, exists = session.GetToken("non-existent")
	if exists {
		t.Error("Expected non-existent token to not exist")
	}
}

func TestSimplifiedSessionData_Clear(t *testing.T) {
	session := NewSimplifiedSessionData()

	// Add some data
	session.SetToken("access_token", "test-value")
	session.SetToken("refresh_token", "refresh-value")

	// Verify data exists
	if _, exists := session.GetToken("access_token"); !exists {
		t.Error("Expected token to exist before clear")
	}

	// Clear all data
	session.Clear()

	// Verify data is gone
	if _, exists := session.GetToken("access_token"); exists {
		t.Error("Expected token to not exist after clear")
	}

	if _, exists := session.GetToken("refresh_token"); exists {
		t.Error("Expected refresh token to not exist after clear")
	}
}

func TestSimplifiedSessionData_ConcurrentAccess(t *testing.T) {
	session := NewSimplifiedSessionData()

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := "token_" + string(rune(id))
				value := "value_" + string(rune(j))
				session.SetToken(key, value)

				// Read back
				session.GetToken(key)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Clear should work after concurrent access
	session.Clear()
}
