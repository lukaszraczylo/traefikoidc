package traefikoidc

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"text/template"
)

// TestTraefikConfigurationParsing tests various ways Traefik might pass configuration
// to the plugin, specifically focusing on the headers field
func TestTraefikConfigurationParsing(t *testing.T) {
	testCases := []struct {
		name        string
		config      *Config
		expectError bool
		description string
	}{
		{
			name: "valid configuration with templated headers",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "test-encryption-key-32-bytes-long",
				CallbackURL:          "/oauth2/callback",
				Headers: []TemplatedHeader{
					{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
				},
			},
			expectError: false,
			description: "Standard configuration should work",
		},
		{
			name: "configuration with multiple headers",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "test-encryption-key-32-bytes-long",
				CallbackURL:          "/oauth2/callback",
				Headers: []TemplatedHeader{
					{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
					{Name: "X-User-Email", Value: "{{.Claims.email}}"},
					{Name: "X-User-ID", Value: "{{.Claims.sub}}"},
				},
			},
			expectError: false,
			description: "Multiple headers should work",
		},
		{
			name: "empty headers configuration",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "test-encryption-key-32-bytes-long",
				CallbackURL:          "/oauth2/callback",
				Headers:              []TemplatedHeader{},
			},
			expectError: false,
			description: "Empty headers should not cause issues",
		},
		{
			name: "nil headers configuration",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "test-encryption-key-32-bytes-long",
				CallbackURL:          "/oauth2/callback",
				Headers:              nil,
			},
			expectError: false,
			description: "Nil headers should be handled gracefully",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a simple next handler
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Try to create the middleware
			ctx := context.Background()
			handler, err := New(ctx, next, tc.config, "test-middleware")

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tc.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.description, err)
				} else {
					// Verify that the middleware was created successfully
					middleware, ok := handler.(*TraefikOidc)
					if !ok {
						t.Fatalf("Handler is not of type *TraefikOidc")
					}

					// Clean up the middleware when test finishes
					defer func() {
						if err := middleware.Close(); err != nil {
							t.Errorf("Failed to close middleware: %v", err)
						}
					}()

					// Check that templates were parsed correctly
					if len(tc.config.Headers) > 0 {
						if len(middleware.headerTemplates) != len(tc.config.Headers) {
							t.Errorf("Expected %d templates, got %d",
								len(tc.config.Headers), len(middleware.headerTemplates))
						}

						// Verify each template can be executed
						for headerName, tmpl := range middleware.headerTemplates {
							testData := map[string]interface{}{
								"AccessToken": "test-token",
								"Claims": map[string]interface{}{
									"email": "test@example.com",
									"sub":   "user123",
								},
							}

							var buf bytes.Buffer
							if err := tmpl.Execute(&buf, testData); err != nil {
								t.Errorf("Failed to execute template for header %s: %v",
									headerName, err)
							}
						}
					}
				}
			}
		})
	}
}

// TestTemplateParsingDuringInitialization specifically tests template parsing
// during middleware initialization to catch any issues that might occur
func TestTemplateParsingDuringInitialization(t *testing.T) {
	// Test various template expressions that might cause issues
	templateTests := []struct {
		name          string
		templateValue string
		shouldFail    bool
	}{
		{
			name:          "simple access token",
			templateValue: "{{.AccessToken}}",
			shouldFail:    false,
		},
		{
			name:          "bearer token format",
			templateValue: "Bearer {{.AccessToken}}",
			shouldFail:    false,
		},
		{
			name:          "nested claim access",
			templateValue: "{{.Claims.email}}",
			shouldFail:    false,
		},
		{
			name:          "multiple template expressions",
			templateValue: "User: {{.Claims.email}}, Token: {{.AccessToken}}",
			shouldFail:    false,
		},
		{
			name:          "invalid template syntax",
			templateValue: "{{.AccessToken",
			shouldFail:    true,
		},
		{
			name:          "empty template",
			templateValue: "",
			shouldFail:    false,
		},
	}

	for _, tt := range templateTests {
		t.Run(tt.name, func(t *testing.T) {
			// Test template parsing directly
			tmpl := template.New("test")
			_, err := tmpl.Parse(tt.templateValue)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected template parsing to fail for %q", tt.templateValue)
				}
			} else {
				if err != nil {
					t.Errorf("Template parsing failed for %q: %v", tt.templateValue, err)
				}
			}
		})
	}
}

// TestIssue55ReproductionAttempt attempts to reproduce the exact scenario
// from GitHub issue #55 where the error occurs during configuration
func TestIssue55ReproductionAttempt(t *testing.T) {
	// Create a configuration exactly as reported by the user
	config := &Config{
		ProviderURL:          "https://accounts.google.com",
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		SessionEncryptionKey: "test-session-encryption-key-32-bytes-long",
		CallbackURL:          "/oauth2/callback",
		LogoutURL:            "/oauth2/logout",
		LogLevel:             "debug",
		Scopes:               []string{"openid", "profile", "email"},
		Headers: []TemplatedHeader{
			{
				Name:  "Authorization",
				Value: "Bearer {{.AccessToken}}",
			},
		},
	}

	// Create a mock HTTP handler
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Try to initialize the middleware
	ctx := context.Background()
	handler, err := New(ctx, next, config, "test-oidc")

	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	// Verify the middleware was created correctly
	middleware, ok := handler.(*TraefikOidc)
	if !ok {
		t.Fatalf("Handler is not of type *TraefikOidc")
	}

	// Clean up the middleware when test finishes
	defer func() {
		if err := middleware.Close(); err != nil {
			t.Errorf("Failed to close middleware: %v", err)
		}
	}()

	// Check that the header template was parsed
	if len(middleware.headerTemplates) != 1 {
		t.Errorf("Expected 1 header template, got %d", len(middleware.headerTemplates))
	}

	// Verify the template exists for the Authorization header
	authTmpl, exists := middleware.headerTemplates["Authorization"]
	if !exists {
		t.Fatal("Authorization template not found")
	}

	// Test executing the template
	templateData := map[string]interface{}{
		"AccessToken": "test-access-token",
		"Claims": map[string]interface{}{
			"email": "user@example.com",
		},
	}

	var buf bytes.Buffer
	if err := authTmpl.Execute(&buf, templateData); err != nil {
		t.Errorf("Failed to execute Authorization template: %v", err)
	}

	expectedValue := "Bearer test-access-token"
	if buf.String() != expectedValue {
		t.Errorf("Expected %q, got %q", expectedValue, buf.String())
	}
}
