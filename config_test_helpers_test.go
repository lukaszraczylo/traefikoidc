package traefikoidc

// Shared Config-fixture helpers for round-regression tests.
//
// Moved here for FIX-41: r134ValidConfig was declared inside review_r134_test.go
// but consumed by review_r135_test.go, so deleting or renaming the declaring
// file silently broke the consumer. Every review_rNN*_test.go file must
// depend only on shared helpers like this one, never on another round file.

// r134ValidConfig returns a minimal Config that passes Validate(), for tests
// that mutate one field and assert the resulting accept/reject outcome.
func r134ValidConfig() *Config {
	return &Config{
		ProviderURL:          "https://provider.example.com",
		CallbackURL:          "/callback",
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		SessionEncryptionKey: "0123456789abcdef0123456789abcdef",
		RateLimit:            CreateConfig().RateLimit,
	}
}
