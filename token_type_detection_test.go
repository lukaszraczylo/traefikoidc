package traefikoidc

import (
	"testing"
	"time"
)

func TestDetectTokenType(t *testing.T) {
	// Create a test instance with mock cache
	tr := &TraefikOidc{
		clientID:               "test-client-id",
		suppressDiagnosticLogs: true,
		tokenTypeCache:         NewTestCache(),
	}

	testCases := []struct {
		name        string
		jwt         *JWT
		token       string
		expectedID  bool
		description string
	}{
		{
			name: "ID token with nonce",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"nonce": "test-nonce",
					"aud":   "test-client-id",
				},
			},
			token:       "test-token-with-nonce",
			expectedID:  true,
			description: "Should detect ID token via nonce claim",
		},
		{
			name: "RFC 9068 access token",
			jwt: &JWT{
				Header: map[string]interface{}{
					"alg": "RS256",
					"typ": "at+jwt",
				},
				Claims: map[string]interface{}{
					"scope": "openid profile",
				},
			},
			token:       "test-access-token-rfc9068",
			expectedID:  false,
			description: "Should detect access token via typ=at+jwt header",
		},
		{
			name: "Token with token_use=id",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"token_use": "id",
					"aud":       "test-client-id",
				},
			},
			token:       "test-token-use-id",
			expectedID:  true,
			description: "Should detect ID token via token_use claim",
		},
		{
			name: "Token with token_use=access",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"token_use": "access",
					"scope":     "read write",
				},
			},
			token:       "test-token-use-access",
			expectedID:  false,
			description: "Should detect access token via token_use claim",
		},
		{
			name: "Access token with scope",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"scope": "openid profile email",
					"aud":   "some-api-audience",
				},
			},
			token:       "test-access-token-with-scope",
			expectedID:  false,
			description: "Should detect access token via scope claim",
		},
		{
			name: "ID token with client_id audience",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"aud": "test-client-id",
					"sub": "user123",
				},
			},
			token:       "test-id-token-client-aud",
			expectedID:  true,
			description: "Should detect ID token via audience matching client_id",
		},
		{
			name: "Default to access token",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"aud": "different-audience",
					"sub": "user123",
				},
			},
			token:       "test-default-access-token",
			expectedID:  false,
			description: "Should default to access token when no clear indicators",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First call - should not be cached
			result := tr.detectTokenType(tc.jwt, tc.token)
			if result != tc.expectedID {
				t.Errorf("%s: expected isIDToken=%v, got %v", tc.description, tc.expectedID, result)
			}

			// Second call - should be cached
			result2 := tr.detectTokenType(tc.jwt, tc.token)
			if result2 != tc.expectedID {
				t.Errorf("%s (cached): expected isIDToken=%v, got %v", tc.description, tc.expectedID, result2)
			}
		})
	}
}

func TestDetectTokenTypeCaching(t *testing.T) {
	cache := NewTestCache()
	tr := &TraefikOidc{
		clientID:               "test-client-id",
		suppressDiagnosticLogs: true,
		tokenTypeCache:         cache,
	}

	jwt := &JWT{
		Header: map[string]interface{}{"alg": "RS256"},
		Claims: map[string]interface{}{
			"nonce": "test-nonce",
		},
	}
	token := "test-token-for-caching-with-enough-characters-for-key"
	cacheKey := token
	if len(token) > 32 {
		cacheKey = token[:32] // First 32 chars
	}

	// First call - should cache
	result := tr.detectTokenType(jwt, token)
	if !result {
		t.Error("Expected ID token detection via nonce")
	}

	// Check cache was populated
	if cached, found := cache.Get(cacheKey); !found {
		t.Error("Expected token type to be cached")
	} else if cachedBool, ok := cached.(bool); !ok || !cachedBool {
		t.Error("Expected cached value to be true (ID token)")
	}

	// Modify JWT to have different detection (but use same token for cache key)
	jwt.Claims = map[string]interface{}{
		"scope": "openid profile", // This would normally make it an access token
	}

	// Second call with modified JWT - should still return cached value
	result2 := tr.detectTokenType(jwt, token)
	if !result2 {
		t.Error("Expected cached ID token result, ignoring modified JWT")
	}
}

// TestCache is a simple in-memory cache for testing
type TestCache struct {
	data map[string]interface{}
}

func NewTestCache() *TestCache {
	return &TestCache{
		data: make(map[string]interface{}),
	}
}

func (c *TestCache) Set(key string, value interface{}, ttl time.Duration) {
	c.data[key] = value
}

func (c *TestCache) Get(key string) (interface{}, bool) {
	val, ok := c.data[key]
	return val, ok
}

func (c *TestCache) Delete(key string) {
	delete(c.data, key)
}

func (c *TestCache) SetMaxSize(size int) {}
func (c *TestCache) Size() int           { return len(c.data) }
func (c *TestCache) Clear()              { c.data = make(map[string]interface{}) }
func (c *TestCache) Cleanup()            {}
func (c *TestCache) Close()              {}
func (c *TestCache) GetStats() map[string]interface{} {
	return map[string]interface{}{"size": len(c.data)}
}
