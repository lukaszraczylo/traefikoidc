package traefikoidc

// Shared *TraefikOidc plugin-construction helper for round-regression tests.
//
// Moved here for FIX-41: newR154TestPlugin was declared inside
// review_r154_regression_test.go but consumed by review_r155_regression_test.go,
// so deleting or renaming the declaring file silently broke the consumer.
// Every review_rNN*_test.go file must depend only on shared helpers like
// this one, never on another round file.

import (
	"context"
	"net/http"
	"testing"
)

// newR154TestPlugin mirrors the standard test setup from audience_test:
// a real middleware instance backed by a real session manager.
func newR154TestPlugin(t *testing.T) *TraefikOidc {
	t.Helper()
	config := CreateConfig()
	config.ProviderURL = "https://provider.example.com"
	config.ClientID = "test-client-id"
	config.ClientSecret = "test-secret"
	config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	config.CallbackURL = "/callback"

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	oidc, err := NewWithContext(context.Background(), config, next, "test")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}
	t.Cleanup(func() { _ = oidc.Close() })
	return oidc
}
