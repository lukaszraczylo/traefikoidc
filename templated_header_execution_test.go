package traefikoidc

import (
	"bytes"
	"testing"
	"text/template"
)

// TestTemplateExecution tests that templates are executed correctly with different types of claims
func TestTemplateExecution(t *testing.T) {
	tests := []struct {
		name          string
		templateText  string
		data          map[string]interface{}
		expectedValue string
		expectError   bool
	}{
		{
			name:         "String Claim",
			templateText: "{{.Claims.email}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"email": "user@example.com",
				},
			},
			expectedValue: "user@example.com",
			expectError:   false,
		},
		{
			name:         "Number Claim",
			templateText: "{{.Claims.age}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"age": 30,
				},
			},
			expectedValue: "30",
			expectError:   false,
		},
		{
			name:         "Boolean Claim",
			templateText: "{{.Claims.admin}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"admin": true,
				},
			},
			expectedValue: "true",
			expectError:   false,
		},
		{
			name:         "Array Claim",
			templateText: "{{index .Claims.roles 0}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"roles": []string{"admin", "user"},
				},
			},
			expectedValue: "admin",
			expectError:   false,
		},
		{
			name:         "Nested Object Claim",
			templateText: "{{.Claims.user.name}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"user": map[string]interface{}{
						"name": "John Doe",
					},
				},
			},
			expectedValue: "John Doe",
			expectError:   false,
		},
		{
			name:         "Access Token",
			templateText: "Bearer {{.AccessToken}}",
			data: map[string]interface{}{
				"AccessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U",
			},
			expectedValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U",
			expectError:   false,
		},
		{
			name:         "ID Token",
			templateText: "{{.IdToken}}",
			data: map[string]interface{}{
				"IdToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U",
			},
			expectedValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U",
			expectError:   false,
		},
		{
			name:         "Refresh Token",
			templateText: "{{.RefreshToken}}",
			data: map[string]interface{}{
				"RefreshToken": "refresh-token-value",
			},
			expectedValue: "refresh-token-value",
			expectError:   false,
		},
		{
			name:         "Conditional Template",
			templateText: "{{if .Claims.admin}}Admin User{{else}}Regular User{{end}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"admin": true,
				},
			},
			expectedValue: "Admin User",
			expectError:   false,
		},
		{
			name:         "Multiple Claims",
			templateText: "{{.Claims.firstName}} {{.Claims.lastName}} <{{.Claims.email}}>",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
					"email":     "john.doe@example.com",
				},
			},
			expectedValue: "John Doe <john.doe@example.com>",
			expectError:   false,
		},
		{
			name:         "Missing Claim",
			templateText: "{{.Claims.missing}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{},
			},
			expectedValue: "<no value>",
			expectError:   false, // Go templates don't error on missing values
		},
		{
			name:         "Invalid Template Syntax",
			templateText: "{{.Claims.email",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"email": "user@example.com",
				},
			},
			expectedValue: "",
			expectError:   true, // Parsing should fail
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)

			if tc.expectError {
				if err == nil {
					t.Fatal("Expected template parsing error, but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.data)
			if err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			result := buf.String()
			if result != tc.expectedValue {
				t.Errorf("Expected template output %q, got %q", tc.expectedValue, result)
			}
		})
	}
}

// TestTemplateExecutionContext tests the specific template data context used in processAuthorizedRequest
func TestTemplateExecutionContext(t *testing.T) {
	// Define a test struct that matches the one used in processAuthorizedRequest
	type templateData struct {
		AccessToken  string
		IdToken      string
		RefreshToken string
		Claims       map[string]interface{}
	}

	// Test cases
	tests := []struct {
		name          string
		templateText  string
		data          templateData
		expectedValue string
	}{
		{
			name:         "Access and ID token distinction",
			templateText: "Access: {{.AccessToken}} ID: {{.IdToken}}",
			data: templateData{
				AccessToken: "access-token-value",
				IdToken:     "id-token-value", // Now these should be distinct values
				Claims:      map[string]interface{}{},
			},
			expectedValue: "Access: access-token-value ID: id-token-value",
		},
		{
			name:         "Combining tokens and claims",
			templateText: "User: {{.Claims.sub}} Token: {{.AccessToken}}",
			data: templateData{
				AccessToken: "access-token",
				IdToken:     "access-token",
				Claims: map[string]interface{}{
					"sub": "user123",
				},
			},
			expectedValue: "User: user123 Token: access-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.data)
			if err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			result := buf.String()
			if result != tc.expectedValue {
				t.Errorf("Expected template output %q, got %q", tc.expectedValue, result)
			}
		})
	}
}
