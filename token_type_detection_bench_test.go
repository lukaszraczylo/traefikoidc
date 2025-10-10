package traefikoidc

import (
	"testing"
	"time"
)

func BenchmarkDetectTokenType(b *testing.B) {
	tr := &TraefikOidc{
		clientID:               "test-client-id",
		suppressDiagnosticLogs: true,
		tokenTypeCache:         NewTestCache(),
	}

	// Create various JWT test cases
	jwtWithNonce := &JWT{
		Header: map[string]interface{}{"alg": "RS256"},
		Claims: map[string]interface{}{
			"nonce": "test-nonce",
			"aud":   "test-client-id",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		},
	}

	jwtWithScope := &JWT{
		Header: map[string]interface{}{"alg": "RS256"},
		Claims: map[string]interface{}{
			"scope": "openid profile email",
			"aud":   "some-api",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		},
	}

	jwtComplexDetection := &JWT{
		Header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		Claims: map[string]interface{}{
			"aud":          []interface{}{"test-client-id", "another-aud"},
			"exp":          time.Now().Add(1 * time.Hour).Unix(),
			"sub":          "user123",
			"token_type":   "Bearer",
			"custom_claim": "value",
		},
	}

	testCases := []struct {
		name  string
		jwt   *JWT
		token string
	}{
		{"WithNonce", jwtWithNonce, "token-with-nonce-for-benchmark-testing-12345678901234567890"},
		{"WithScope", jwtWithScope, "token-with-scope-for-benchmark-testing-12345678901234567890"},
		{"ComplexDetection", jwtComplexDetection, "token-complex-for-benchmark-testing-12345678901234567890"},
	}

	for _, tc := range testCases {
		b.Run(tc.name+"_FirstCall", func(b *testing.B) {
			// Benchmark first call (uncached)
			for i := 0; i < b.N; i++ {
				// Clear cache before each iteration
				tr.tokenTypeCache.Clear()
				_ = tr.detectTokenType(tc.jwt, tc.token)
			}
		})

		b.Run(tc.name+"_Cached", func(b *testing.B) {
			// Prime the cache
			_ = tr.detectTokenType(tc.jwt, tc.token)

			// Benchmark cached calls
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = tr.detectTokenType(tc.jwt, tc.token)
			}
		})
	}
}

// Benchmark comparison with the old implementation logic
func BenchmarkOldDetectionLogic(b *testing.B) {
	clientID := "test-client-id"

	jwt := &JWT{
		Header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		Claims: map[string]interface{}{
			"aud":          []interface{}{"test-client-id", "another-aud"},
			"exp":          time.Now().Add(1 * time.Hour).Unix(),
			"sub":          "user123",
			"token_type":   "Bearer",
			"custom_claim": "value",
		},
	}

	b.Run("OldLogic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Simulate the old detection logic (all 6 sequential checks)
			isIDToken := false
			isAccessToken := false

			// Step 1: Check typ header
			if typ, ok := jwt.Header["typ"].(string); ok {
				if typ == "at+jwt" {
					isAccessToken = true
				}
			}

			// Step 2: Check token_use claim
			if !isAccessToken && !isIDToken {
				if tokenUse, ok := jwt.Claims["token_use"].(string); ok {
					if tokenUse == "access" {
						isAccessToken = true
					} else if tokenUse == "id" {
						isIDToken = true
					}
				}
			}

			// Step 3: Check token_type claim
			if !isAccessToken && !isIDToken {
				if tokenType, ok := jwt.Claims["token_type"].(string); ok {
					if tokenType == "access_token" || tokenType == "Bearer" {
						isAccessToken = true
					} else if tokenType == "id_token" {
						isIDToken = true
					}
				}
			}

			// Step 4: Check scope claim
			if !isAccessToken && !isIDToken {
				if scope, ok := jwt.Claims["scope"]; ok {
					if _, ok := scope.(string); ok {
						isAccessToken = true
					}
				}
			}

			// Step 5: Check nonce claim
			if !isAccessToken && !isIDToken {
				if nonce, ok := jwt.Claims["nonce"]; ok {
					if _, ok := nonce.(string); ok {
						isIDToken = true
					}
				}
			}

			// Step 6: Check audience
			if !isAccessToken && !isIDToken {
				if aud, ok := jwt.Claims["aud"]; ok {
					if audStr, ok := aud.(string); ok && audStr == clientID {
						isIDToken = true
					}
					if audArr, ok := aud.([]interface{}); ok {
						for _, v := range audArr {
							if str, ok := v.(string); ok && str == clientID {
								if len(audArr) == 1 {
									isIDToken = true
								}
								break
							}
						}
					}
				}
			}

			// Step 7: Default to access token
			if !isIDToken {
				isAccessToken = true
			}

			_ = isAccessToken
		}
	})
}
