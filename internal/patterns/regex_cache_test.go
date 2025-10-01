package patterns

import (
	"regexp"
	"sync"
	"testing"
)

func TestRegexCache_Get(t *testing.T) {
	cache := NewRegexCache()

	pattern := `^test\d+$`

	// First call should compile and cache
	regex1, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to get regex: %v", err)
	}

	// Second call should return cached version
	regex2, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to get cached regex: %v", err)
	}

	// Should be the same instance
	if regex1 != regex2 {
		t.Error("Expected same regex instance from cache")
	}

	// Test the regex works
	if !regex1.MatchString("test123") {
		t.Error("Regex should match 'test123'")
	}

	if regex1.MatchString("test") {
		t.Error("Regex should not match 'test'")
	}
}

func TestRegexCache_ConcurrentAccess(t *testing.T) {
	cache := NewRegexCache()
	pattern := `^concurrent\d+$`

	var wg sync.WaitGroup
	results := make([]*regexp.Regexp, 10)
	errors := make([]error, 10)

	// Launch multiple goroutines to access the same pattern
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			regex, err := cache.Get(pattern)
			results[index] = regex
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// Check all succeeded
	for i, err := range errors {
		if err != nil {
			t.Fatalf("Goroutine %d failed: %v", i, err)
		}
	}

	// All should return the same instance
	first := results[0]
	for i, regex := range results[1:] {
		if regex != first {
			t.Errorf("Goroutine %d got different regex instance", i+1)
		}
	}
}

func TestRegexCache_InvalidPattern(t *testing.T) {
	cache := NewRegexCache()

	_, err := cache.Get(`[invalid`)
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}
}

func TestRegexCache_Precompile(t *testing.T) {
	cache := NewRegexCache()

	patterns := []string{
		`^test1$`,
		`^test2$`,
		`^test3$`,
	}

	err := cache.Precompile(patterns)
	if err != nil {
		t.Fatalf("Failed to precompile patterns: %v", err)
	}

	if cache.Size() != 3 {
		t.Errorf("Expected cache size 3, got %d", cache.Size())
	}

	// Should be able to get precompiled patterns without error
	for _, pattern := range patterns {
		_, err := cache.Get(pattern)
		if err != nil {
			t.Errorf("Failed to get precompiled pattern %s: %v", pattern, err)
		}
	}
}

func TestValidationFunctions(t *testing.T) {
	tests := []struct {
		name     string
		function func(string) bool
		valid    []string
		invalid  []string
	}{
		{
			name:     "ValidateEmail",
			function: ValidateEmail,
			valid:    []string{"test@example.com", "user.name@domain.org", "admin+tag@company.co.uk"},
			invalid:  []string{"invalid-email", "@domain.com", "user@", ""},
		},
		{
			name:     "ValidateDomain",
			function: ValidateDomain,
			valid:    []string{"example.com", "sub.domain.org", "test.co.uk"},
			invalid:  []string{"", "invalid..domain", ".example.com", "domain."},
		},
		{
			name:     "ValidateJWT",
			function: ValidateJWT,
			valid:    []string{"eyJ0.eyJ1.sig", "a.b.c"},
			invalid:  []string{"invalid", "a.b", "a.b.c.d", ""},
		},
		{
			name:     "ValidateClientID",
			function: ValidateClientID,
			valid:    []string{"client123", "my-client_id", "123.456"},
			invalid:  []string{"", "client with spaces", "client@invalid"},
		},
		{
			name:     "ValidateURL",
			function: ValidateURL,
			valid:    []string{"https://example.com", "https://sub.domain.org/path", "http://localhost", "https://example.com/path?query=value", "http://192.168.1.1"},
			invalid:  []string{"", "ftp://example.com", "not-a-url", "https://", "example.com", "http://localhost:8080"},
		},
		{
			name:     "ValidateScopes",
			function: ValidateScopes,
			valid:    []string{"openid", "openid profile", "read write admin", "user_info"},
			invalid:  []string{"", "scope-with-dash", "scope@invalid", "scope with.dot", "  "},
		},
		{
			name:     "ValidateSessionID",
			function: ValidateSessionID,
			valid:    []string{"a1b2c3d4e5f6789012345678901234567890abcdef", "ABCDEF1234567890abcdef1234567890", "0123456789abcdef0123456789abcdef"},
			invalid:  []string{"", "too-short", "contains-invalid-chars!", "g123456789abcdef0123456789abcdef", "1234567890abcdef1234567890abcde"},
		},
		{
			name:     "ValidateCSRFToken",
			function: ValidateCSRFToken,
			valid:    []string{"abc123", "ABC_123-xyz", "token-value_123", "_valid-token_"},
			invalid:  []string{"", "token with spaces", "token@invalid", "token.with.dots!", "token/with/slash"},
		},
		{
			name:     "ValidateNonce",
			function: ValidateNonce,
			valid:    []string{"abc123", "ABC_123-xyz", "nonce-value_123", "_valid-nonce_"},
			invalid:  []string{"", "nonce with spaces", "nonce@invalid", "nonce.with.dots!", "nonce/with/slash"},
		},
		{
			name:     "ValidateCodeVerifier",
			function: ValidateCodeVerifier,
			valid:    []string{"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"},
			invalid:  []string{"", "too-short", "short", "verifier with spaces", "verifier@invalid", "a"},
		},
		{
			name:     "ValidateAuthCode",
			function: ValidateAuthCode,
			valid:    []string{"auth_code_123", "ABC.123-xyz/code+value=", "simple-code"},
			invalid:  []string{"", "code with spaces", "code@invalid"},
		},
		{
			name:     "ValidateRedirectURI",
			function: ValidateRedirectURI,
			valid:    []string{"https://example.com/callback", "http://localhost:8080/auth", "https://app.example.org/oauth/callback", "http://127.0.0.1:3000"},
			invalid:  []string{"", "ftp://example.com", "not-a-url", "example.com/callback", "https://"},
		},
		{
			name:     "ValidateIPv4",
			function: ValidateIPv4,
			valid:    []string{"192.168.1.1", "10.0.0.1", "127.0.0.1", "255.255.255.255", "0.0.0.0"},
			invalid:  []string{"", "256.1.1.1", "192.168.1", "192.168.1.1.1", "not-an-ip"},
		},
		{
			name:     "ValidateTenantID",
			function: ValidateTenantID,
			valid:    []string{"12345678-1234-1234-1234-123456789abc", "ABCDEF12-3456-7890-ABCD-EF1234567890"},
			invalid:  []string{"", "not-a-uuid", "12345678-1234-1234-1234", "12345678-1234-1234-1234-123456789abcd", "123456781234123412341234567890ab"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, valid := range tt.valid {
				if !tt.function(valid) {
					t.Errorf("%s should be valid: %s", tt.name, valid)
				}
			}

			for _, invalid := range tt.invalid {
				if tt.function(invalid) {
					t.Errorf("%s should be invalid: %s", tt.name, invalid)
				}
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		header   string
		expected string
		valid    bool
	}{
		{"Bearer abc123", "abc123", true},
		{"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9", true},
		{"bearer token123", "", false}, // case sensitive
		{"Basic abc123", "", false},
		{"Bearer", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		token, valid := ExtractBearerToken(tt.header)
		if valid != tt.valid {
			t.Errorf("ExtractBearerToken(%q) valid = %v, want %v", tt.header, valid, tt.valid)
		}
		if token != tt.expected {
			t.Errorf("ExtractBearerToken(%q) token = %q, want %q", tt.header, token, tt.expected)
		}
	}
}

func BenchmarkRegexCache_Get(b *testing.B) {
	cache := NewRegexCache()
	pattern := `^benchmark\d+$`

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cache.Get(pattern)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRegexCache_Validation(b *testing.B) {
	email := "test@example.com"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ValidateEmail(email)
		}
	})
}

func BenchmarkRegex_DirectCompile(b *testing.B) {
	pattern := `^benchmark\d+$`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := regexp.Compile(pattern)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestRegexCache_Clear(t *testing.T) {
	cache := NewRegexCache()

	// Add some patterns to the cache
	patterns := []string{`^test1$`, `^test2$`, `^test3$`}
	for _, pattern := range patterns {
		_, err := cache.Get(pattern)
		if err != nil {
			t.Fatalf("Failed to add pattern %s: %v", pattern, err)
		}
	}

	// Verify cache has patterns
	if cache.Size() != 3 {
		t.Errorf("Expected cache size 3, got %d", cache.Size())
	}

	// Clear the cache
	cache.Clear()

	// Verify cache is empty
	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", cache.Size())
	}
}

func TestIsBotUserAgent(t *testing.T) {
	tests := []struct {
		userAgent string
		isBot     bool
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
		{"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", false},
		{"crawler-bot/1.0", true},
		{"spider-agent/2.0", true},
		{"curl/7.68.0", true},
		{"wget/1.20.3", true},
		{"python-requests/2.25.1", true},
		{"Go-http-client/1.1", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.userAgent, func(t *testing.T) {
			result := IsBotUserAgent(tt.userAgent)
			if result != tt.isBot {
				t.Errorf("IsBotUserAgent(%q) = %v, want %v", tt.userAgent, result, tt.isBot)
			}
		})
	}
}

func TestGetGlobalCache(t *testing.T) {
	cache := GetGlobalCache()
	if cache == nil {
		t.Error("GetGlobalCache() should not return nil")
	}

	// Should return the same instance
	cache2 := GetGlobalCache()
	if cache != cache2 {
		t.Error("GetGlobalCache() should return the same instance")
	}

	// Should have precompiled patterns
	if cache.Size() == 0 {
		t.Error("Global cache should have precompiled patterns")
	}
}

func TestCompilePattern(t *testing.T) {
	pattern := `^test_compile\d+$`

	regex, err := CompilePattern(pattern)
	if err != nil {
		t.Fatalf("CompilePattern failed: %v", err)
	}

	if !regex.MatchString("test_compile123") {
		t.Error("Compiled pattern should match 'test_compile123'")
	}

	if regex.MatchString("test_compile") {
		t.Error("Compiled pattern should not match 'test_compile'")
	}

	// Test invalid pattern
	_, err = CompilePattern(`[invalid`)
	if err == nil {
		t.Error("Expected error for invalid pattern")
	}
}

func TestMustCompilePattern(t *testing.T) {
	pattern := `^test_must_compile\d+$`

	regex := MustCompilePattern(pattern)
	if regex == nil {
		t.Fatal("MustCompilePattern should not return nil")
	}

	if !regex.MatchString("test_must_compile456") {
		t.Error("Compiled pattern should match 'test_must_compile456'")
	}

	// Test that it panics with invalid pattern
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustCompilePattern should panic with invalid pattern")
		}
	}()
	MustCompilePattern(`[invalid`)
}

func TestAdditionalValidationEdgeCases(t *testing.T) {
	// Test edge cases for ValidateURL
	t.Run("ValidateURL_EdgeCases", func(t *testing.T) {
		edgeCases := []struct {
			url   string
			valid bool
		}{
			{"https://a.b", true},
			{"http://localhost", true},
			{"https://example.com/path?query=value#fragment", true},
			{"http://192.168.0.1:8080/api", false},
			{"https://", false},
			{"http://", false},
			{"https://example", true},
		}

		for _, tc := range edgeCases {
			result := ValidateURL(tc.url)
			if result != tc.valid {
				t.Errorf("ValidateURL(%q) = %v, want %v", tc.url, result, tc.valid)
			}
		}
	})

	// Test edge cases for ValidateScopes
	t.Run("ValidateScopes_EdgeCases", func(t *testing.T) {
		edgeCases := []struct {
			scopes string
			valid  bool
		}{
			{"a", true},
			{"a b", true},
			{"openid profile email", true},
			{"user_profile", true},
			{"read_all write_all", true},
			{"scope-with-dash", false},
			{"scope.with.dot", false},
			{"scope@email", false},
			{" scope", false},
			{"scope ", false},
			{"a  b", true}, // pattern allows multiple spaces
		}

		for _, tc := range edgeCases {
			result := ValidateScopes(tc.scopes)
			if result != tc.valid {
				t.Errorf("ValidateScopes(%q) = %v, want %v", tc.scopes, result, tc.valid)
			}
		}
	})

	// Test edge cases for ValidateSessionID
	t.Run("ValidateSessionID_EdgeCases", func(t *testing.T) {
		edgeCases := []struct {
			sessionID string
			valid     bool
		}{
			{"12345678901234567890123456789012", true},                             // 32 chars (min)
			{"1234567890123456789012345678901", false},                             // 31 chars (too short)
			{string(make([]byte, 128)), false},                                     // 128 non-hex chars
			{"abcdef1234567890ABCDEF1234567890" + string(make([]byte, 96)), false}, // 128+ chars with non-hex
		}

		// Generate valid 128-char hex string (max length)
		validLongHex := ""
		for i := 0; i < 128; i++ {
			validLongHex += "a"
		}
		edgeCases = append(edgeCases, struct {
			sessionID string
			valid     bool
		}{validLongHex, true})

		for _, tc := range edgeCases {
			result := ValidateSessionID(tc.sessionID)
			if result != tc.valid {
				t.Errorf("ValidateSessionID(%q) = %v, want %v", tc.sessionID, result, tc.valid)
			}
		}
	})
}
