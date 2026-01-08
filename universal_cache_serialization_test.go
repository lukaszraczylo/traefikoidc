package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUniversalCache_SerializeDeserialize tests the fix for issue #116
// where metadata was stored as Base64-encoded JSON but read as plain JSON
func TestUniversalCache_SerializeDeserialize(t *testing.T) {
	t.Parallel()

	t.Run("RawBytesPreserved", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		// Test data: pre-marshaled JSON bytes (like metadata_cache uses)
		testData := []byte(`{"issuer":"https://example.com","jwks_uri":"https://example.com/jwks"}`)

		// Serialize
		serialized, err := cache.serialize(testData)
		require.NoError(t, err)
		assert.NotNil(t, serialized)

		// Should have marker byte
		assert.Equal(t, byte(0x00), serialized[0], "Should have raw bytes marker")
		assert.Equal(t, testData, serialized[1:], "Data should be preserved after marker")

		// Deserialize
		var result interface{}
		err = cache.deserialize(serialized, &result)
		require.NoError(t, err)

		// Should get back []byte
		resultBytes, ok := result.([]byte)
		require.True(t, ok, "Result should be []byte")
		assert.Equal(t, testData, resultBytes, "Deserialized data should match original")
	})

	t.Run("JSONEncodedTypes", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		testCases := []struct {
			name  string
			value interface{}
		}{
			{
				name:  "Map",
				value: map[string]interface{}{"key": "value", "number": 42.0},
			},
			{
				name:  "String",
				value: "test-string",
			},
			{
				name:  "Number",
				value: 123.456,
			},
			{
				name:  "Array",
				value: []interface{}{"a", "b", "c"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Serialize
				serialized, err := cache.serialize(tc.value)
				require.NoError(t, err)
				assert.NotNil(t, serialized)

				// Should have JSON marker byte
				assert.Equal(t, byte(0x01), serialized[0], "Should have JSON marker")

				// Verify the JSON portion is valid
				var checkJSON interface{}
				err = json.Unmarshal(serialized[1:], &checkJSON)
				require.NoError(t, err, "Should be valid JSON after marker")

				// Deserialize
				var result interface{}
				err = cache.deserialize(serialized, &result)
				require.NoError(t, err)

				// Compare results (using JSON round-trip for consistent comparison)
				expectedJSON, _ := json.Marshal(tc.value)
				resultJSON, _ := json.Marshal(result)
				assert.JSONEq(t, string(expectedJSON), string(resultJSON), "Deserialized data should match original")
			})
		}
	})

	t.Run("LegacyDataCompatibility", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		// Simulate legacy data (JSON without marker byte)
		legacyData := []byte(`{"legacy":"data"}`)

		var result interface{}
		err := cache.deserialize(legacyData, &result)
		require.NoError(t, err)

		// Should successfully unmarshal as JSON
		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok, "Should unmarshal legacy JSON data")
		assert.Equal(t, "data", resultMap["legacy"])
	})

	t.Run("EmptyDataHandling", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		var result interface{}
		err := cache.deserialize([]byte{}, &result)
		assert.Error(t, err, "Should error on empty data")
		assert.Contains(t, err.Error(), "empty data")
	})

	t.Run("OverflowProtection_LargeBytes", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		// Create a byte slice that exceeds maxCacheEntrySize (64 MiB)
		oversizedBytes := make([]byte, 65*1024*1024) // 65 MiB

		// Attempt to serialize - should fail with overflow error
		_, err := cache.serialize(oversizedBytes)
		require.Error(t, err, "Should error on oversized byte slice")
		assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	})

	t.Run("OverflowProtection_ExactMaxSize", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		// Create a byte slice exactly at maxCacheEntrySize
		// This should fail because adding marker byte would overflow
		exactMaxBytes := make([]byte, 64*1024*1024) // Exactly 64 MiB

		_, err := cache.serialize(exactMaxBytes)
		require.Error(t, err, "Should error when adding marker would overflow")
		assert.Contains(t, err.Error(), "would overflow when adding marker byte")
	})

	t.Run("OverflowProtection_SafeSize", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		// Create a byte slice well within limits
		safeBytes := make([]byte, 1024*1024) // 1 MiB - safe size

		serialized, err := cache.serialize(safeBytes)
		require.NoError(t, err, "Should succeed with safe size")
		assert.NotNil(t, serialized)
		assert.Equal(t, len(safeBytes)+1, len(serialized), "Should add marker byte")
	})

	t.Run("OverflowProtection_JSONData", func(t *testing.T) {
		cache := NewUniversalCache(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		})
		defer cache.Close()

		// Create a very large map that will exceed limits when JSON-encoded
		largeMap := make(map[string]string)
		// Each entry is roughly 50 bytes, so we need ~1.3M entries to exceed 64 MiB
		for i := 0; i < 1400000; i++ {
			key := fmt.Sprintf("key_%d", i)
			largeMap[key] = "value_with_some_content_to_make_it_larger"
		}

		_, err := cache.serialize(largeMap)
		require.Error(t, err, "Should error when JSON serialization exceeds size limit")
		assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	})
}

// TestUniversalCache_RedisIntegration_Issue116 tests the complete fix for issue #116
// with actual Redis backend to ensure metadata cache works correctly
func TestUniversalCache_RedisIntegration_Issue116(t *testing.T) {
	t.Parallel()

	// Start miniredis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis backend
	redisConfig := backends.DefaultRedisConfig(mr.Addr())
	redisConfig.RedisPrefix = "test:"
	backend, err := backends.NewRedisBackend(redisConfig)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("MetadataCache_StoreAndRetrieve", func(t *testing.T) {
		// Create cache with Redis backend
		cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
			Type:    CacheTypeMetadata,
			MaxSize: 100,
		}, backend)
		defer cache.Close()

		// Simulate metadata_cache.Set behavior:
		// 1. Marshal metadata to JSON
		metadata := ProviderMetadata{
			Issuer:   "https://example.com",
			JWKSURL:  "https://example.com/jwks",
			TokenURL: "https://example.com/token",
			AuthURL:  "https://example.com/authorize",
		}
		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		// 2. Store the JSON bytes
		key := "v2:https://example.com"
		err = cache.Set(key, jsonData, 1*time.Hour)
		require.NoError(t, err)

		// 3. Retrieve the data
		retrieved, exists := cache.Get(key)
		require.True(t, exists, "Data should exist in cache")

		// 4. Should get back []byte (not a string or map)
		retrievedBytes, ok := retrieved.([]byte)
		require.True(t, ok, "Retrieved value should be []byte, got %T", retrieved)

		// 5. Should be able to unmarshal as JSON
		var retrievedMetadata ProviderMetadata
		err = json.Unmarshal(retrievedBytes, &retrievedMetadata)
		require.NoError(t, err, "Should be able to unmarshal retrieved bytes as JSON")

		// 6. Verify data integrity
		assert.Equal(t, metadata.Issuer, retrievedMetadata.Issuer)
		assert.Equal(t, metadata.JWKSURL, retrievedMetadata.JWKSURL)
		assert.Equal(t, metadata.TokenURL, retrievedMetadata.TokenURL)
	})

	t.Run("MetadataCache_NoBase64Encoding", func(t *testing.T) {
		cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
			Type:    CacheTypeMetadata,
			MaxSize: 100,
		}, backend)
		defer cache.Close()

		// Store JSON bytes
		jsonData := []byte(`{"issuer":"https://test.com"}`)
		key := "v2:https://test.com"
		err = cache.Set(key, jsonData, 1*time.Hour)
		require.NoError(t, err)

		// Retrieve
		retrieved, exists := cache.Get(key)
		require.True(t, exists)

		retrievedBytes, ok := retrieved.([]byte)
		require.True(t, ok)

		// The retrieved data should NOT start with "eyJ" (Base64 encoding of "{")
		// This was the bug in issue #116
		assert.NotEqual(t, []byte("eyJ"), retrievedBytes[:3], "Data should not be Base64 encoded")

		// Should be valid JSON
		var checkJSON map[string]interface{}
		err = json.Unmarshal(retrievedBytes, &checkJSON)
		require.NoError(t, err, "Data should be valid JSON")
		assert.Equal(t, "https://test.com", checkJSON["issuer"])
	})

	t.Run("TokenCache_MapValues", func(t *testing.T) {
		cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
			Type:    CacheTypeToken,
			MaxSize: 100,
		}, backend)
		defer cache.Close()

		// Store a map (like TokenCache does)
		claims := map[string]interface{}{
			"sub":   "user123",
			"exp":   1234567890.0,
			"scope": "read write",
		}
		key := "token:abc123"
		err = cache.Set(key, claims, 10*time.Minute)
		require.NoError(t, err)

		// Retrieve
		retrieved, exists := cache.Get(key)
		require.True(t, exists)

		// Should get back a map
		retrievedMap, ok := retrieved.(map[string]interface{})
		require.True(t, ok, "Retrieved value should be map[string]interface{}")
		assert.Equal(t, "user123", retrievedMap["sub"])
		assert.Equal(t, 1234567890.0, retrievedMap["exp"])
	})

	t.Run("MixedTypes_SameCache", func(t *testing.T) {
		cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		}, backend)
		defer cache.Close()

		// Store different types
		jsonBytes := []byte(`{"type":"json-bytes"}`)
		err = cache.Set("key1", jsonBytes, 1*time.Hour)
		require.NoError(t, err)

		mapData := map[string]interface{}{"type": "map"}
		err = cache.Set("key2", mapData, 1*time.Hour)
		require.NoError(t, err)

		stringData := "plain-string"
		err = cache.Set("key3", stringData, 1*time.Hour)
		require.NoError(t, err)

		// Retrieve and verify each type
		val1, exists := cache.Get("key1")
		require.True(t, exists)
		bytes1, ok := val1.([]byte)
		require.True(t, ok)
		assert.Equal(t, jsonBytes, bytes1)

		val2, exists := cache.Get("key2")
		require.True(t, exists)
		map2, ok := val2.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "map", map2["type"])

		val3, exists := cache.Get("key3")
		require.True(t, exists)
		str3, ok := val3.(string)
		require.True(t, ok)
		assert.Equal(t, stringData, str3)
	})
}

// TestUniversalCache_BackwardCompatibility tests that old cached data is handled gracefully
func TestUniversalCache_BackwardCompatibility(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisConfig := backends.DefaultRedisConfig(mr.Addr())
	backend, err := backends.NewRedisBackend(redisConfig)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("LegacyJSONData", func(t *testing.T) {
		// Manually insert legacy data (plain JSON without marker)
		legacyKey := "general:legacy-key"
		legacyData := []byte(`{"old":"format"}`)
		err = backend.Set(ctx, legacyKey, legacyData, 1*time.Hour)
		require.NoError(t, err)

		// Try to retrieve via UniversalCache
		cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		}, backend)
		defer cache.Close()

		retrieved, exists := cache.Get("legacy-key")
		require.True(t, exists, "Should retrieve legacy data")

		// Should deserialize as JSON map
		retrievedMap, ok := retrieved.(map[string]interface{})
		require.True(t, ok, "Should unmarshal legacy JSON")
		assert.Equal(t, "format", retrievedMap["old"])
	})

	t.Run("LegacyCorruptData", func(t *testing.T) {
		// Insert corrupt/invalid data
		corruptKey := "general:corrupt-key"
		corruptData := []byte("not json and no marker")
		err = backend.Set(ctx, corruptKey, corruptData, 1*time.Hour)
		require.NoError(t, err)

		cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 100,
		}, backend)
		defer cache.Close()

		retrieved, exists := cache.Get("corrupt-key")
		require.True(t, exists)

		// Should return as raw bytes (fallback)
		retrievedBytes, ok := retrieved.([]byte)
		require.True(t, ok, "Should return corrupt data as raw bytes")
		assert.Equal(t, corruptData, retrievedBytes)
	})
}

// TestMetadataCache_Issue116_Regression is the main regression test for issue #116
// This specifically tests the scenario described in the GitHub issue
func TestMetadataCache_Issue116_Regression(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis backend
	redisConfig := backends.DefaultRedisConfig(mr.Addr())
	redisConfig.RedisPrefix = "traefik:"
	backend, err := backends.NewRedisBackend(redisConfig)
	require.NoError(t, err)
	defer backend.Close()

	// Create a simple logger
	logger := GetSingletonNoOpLogger()

	// Create metadata cache instance
	metadataCache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeMetadata,
		MaxSize:         100,
		Logger:          logger,
		SkipAutoCleanup: true,
	}, backend)
	defer metadataCache.Close()

	// Use the actual MetadataCache wrapper
	wg := &sync.WaitGroup{}
	mc := &MetadataCache{
		cache:  metadataCache,
		logger: logger,
		wg:     wg,
	}

	// Test: Store and retrieve metadata (the scenario from issue #116)
	providerURL := "https://example.com"
	metadata := &ProviderMetadata{
		Issuer:         "https://example.com",
		AuthURL:        "https://example.com/authorize",
		TokenURL:       "https://example.com/token",
		JWKSURL:        "https://example.com/jwks",
		RevokeURL:      "https://example.com/revoke",
		EndSessionURL:  "https://example.com/logout",
		RegistrationURL: "https://example.com/register",
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	// Store metadata
	err = mc.Set(providerURL, metadata, 1*time.Hour)
	require.NoError(t, err, "Should store metadata without error")

	// Retrieve metadata
	retrieved, exists := mc.Get(providerURL)
	require.True(t, exists, "Should retrieve stored metadata")
	require.NotNil(t, retrieved, "Retrieved metadata should not be nil")

	// Verify no corruption - this was failing in issue #116 with "invalid character 'e'" error
	assert.Equal(t, metadata.Issuer, retrieved.Issuer)
	assert.Equal(t, metadata.AuthURL, retrieved.AuthURL)
	assert.Equal(t, metadata.TokenURL, retrieved.TokenURL)
	assert.Equal(t, metadata.JWKSURL, retrieved.JWKSURL)

	// Verify the data is not Base64-encoded in Redis
	// This checks the root cause mentioned in the issue
	ctx := context.Background()
	rawData, _, exists, err := backend.Get(ctx, "metadata:v2:"+providerURL)
	require.NoError(t, err)
	require.True(t, exists)

	// Strip the marker byte
	require.Greater(t, len(rawData), 1, "Data should have marker byte")
	dataWithoutMarker := rawData[1:]

	// Should not start with "eyJ" (Base64 encoding of "{")
	if len(dataWithoutMarker) >= 3 {
		assert.NotEqual(t, "eyJ", string(dataWithoutMarker[:3]), "Data should not be Base64-encoded")
	}

	// Should be valid JSON
	var checkMetadata ProviderMetadata
	err = json.Unmarshal(dataWithoutMarker, &checkMetadata)
	require.NoError(t, err, "Stored data should be valid JSON, not Base64")
	assert.Equal(t, metadata.Issuer, checkMetadata.Issuer)
}
