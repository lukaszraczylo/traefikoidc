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
