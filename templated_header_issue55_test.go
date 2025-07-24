package traefikoidc

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
)

// TestIssue55TemplateExecutionWithWrongTypes tests what happens when templates
// receive wrong data types during execution - this reproduces the exact error
// from GitHub issue #55: "can't evaluate field AccessToken in type bool"
func TestIssue55TemplateExecutionWithWrongTypes(t *testing.T) {
	testCases := []struct {
		name          string
		templateText  string
		templateData  interface{}
		expectError   bool
		errorContains string
	}{
		{
			name:         "correct map data",
			templateText: "Bearer {{.AccessToken}}",
			templateData: map[string]interface{}{
				"AccessToken": "valid-token",
			},
			expectError: false,
		},
		{
			name:          "boolean as root context - reproduces issue #55",
			templateText:  "Bearer {{.AccessToken}}",
			templateData:  true,
			expectError:   true,
			errorContains: "can't evaluate field AccessToken in type bool",
		},
		{
			name:          "string as root context",
			templateText:  "Bearer {{.AccessToken}}",
			templateData:  "just a string",
			expectError:   true,
			errorContains: "can't evaluate field AccessToken in type string",
		},
		{
			name:          "nil as root context",
			templateText:  "Bearer {{.AccessToken}}",
			templateData:  nil,
			expectError:   false, // nil renders as <no value>
			errorContains: "",
		},
		{
			name:         "map with wrong field type",
			templateText: "Bearer {{.AccessToken}}",
			templateData: map[string]interface{}{
				"AccessToken": true, // boolean instead of string
			},
			expectError: false, // This should work, template will convert bool to string
		},
		{
			name:         "nested claims access with correct data",
			templateText: "User: {{.Claims.email}}",
			templateData: map[string]interface{}{
				"Claims": map[string]interface{}{
					"email": "user@example.com",
				},
			},
			expectError: false,
		},
		{
			name:         "nested claims with wrong structure",
			templateText: "User: {{.Claims.email}}",
			templateData: map[string]interface{}{
				"Claims": "not a map", // string instead of map
			},
			expectError:   true,
			errorContains: "can't evaluate field email in type", // interface{} or string
		},
		{
			name:          "array as root context",
			templateText:  "Bearer {{.AccessToken}}",
			templateData:  []string{"item1", "item2"},
			expectError:   true,
			errorContains: "can't evaluate field AccessToken in type []string",
		},
		{
			name:          "integer as root context",
			templateText:  "Bearer {{.AccessToken}}",
			templateData:  42,
			expectError:   true,
			errorContains: "can't evaluate field AccessToken in type int",
		},
		{
			name:         "empty template data map",
			templateText: "Bearer {{.AccessToken}}",
			templateData: map[string]interface{}{},
			expectError:  false, // Should render as "Bearer <no value>"
		},
		{
			name:         "complex nested structure",
			templateText: "{{.Claims.sub}} - {{.Claims.groups}} - {{.AccessToken}}",
			templateData: map[string]interface{}{
				"AccessToken": "token123",
				"Claims": map[string]interface{}{
					"sub":    "user-id",
					"groups": "admin,users",
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.templateData)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none, output: %q", buf.String())
				}
				if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tc.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestIssue55TemplateParsingValidation ensures templates are parsed correctly
// and validates the template data structure used in the middleware
func TestIssue55TemplateParsingValidation(t *testing.T) {
	testCases := []struct {
		name            string
		headerTemplates []TemplatedHeader
		shouldError     bool
	}{
		{
			name: "valid bearer token template",
			headerTemplates: []TemplatedHeader{
				{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
			},
			shouldError: false,
		},
		{
			name: "multiple valid templates",
			headerTemplates: []TemplatedHeader{
				{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-ID", Value: "{{.Claims.sub}}"},
			},
			shouldError: false,
		},
		{
			name: "template with conditional logic",
			headerTemplates: []TemplatedHeader{
				{Name: "X-Auth-Info", Value: "{{if .AccessToken}}Bearer {{.AccessToken}}{{else}}No Token{{end}}"},
			},
			shouldError: false,
		},
		{
			name: "invalid template syntax",
			headerTemplates: []TemplatedHeader{
				{Name: "Bad-Template", Value: "{{.AccessToken"},
			},
			shouldError: true,
		},
		{
			name: "empty template value",
			headerTemplates: []TemplatedHeader{
				{Name: "Empty-Header", Value: ""},
			},
			shouldError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, header := range tc.headerTemplates {
				tmpl, err := template.New(header.Name).Parse(header.Value)

				if tc.shouldError {
					if err == nil {
						t.Errorf("Expected template parsing to fail for %s", header.Name)
					}
				} else {
					if err != nil {
						t.Errorf("Failed to parse template for header %s: %v", header.Name, err)
						continue
					}

					// Test execution with correct data structure
					templateData := map[string]interface{}{
						"AccessToken":  "test-access-token",
						"IDToken":      "test-id-token",
						"RefreshToken": "test-refresh-token",
						"Claims": map[string]interface{}{
							"email": "test@example.com",
							"sub":   "user123",
						},
					}

					var buf bytes.Buffer
					err = tmpl.Execute(&buf, templateData)
					if err != nil {
						t.Errorf("Failed to execute valid template: %v", err)
					}
				}
			}
		})
	}
}

// TestIssue55MiddlewareHeaderTemplating simulates the actual middleware flow
// to ensure templated headers work correctly in request processing
func TestIssue55MiddlewareHeaderTemplating(t *testing.T) {
	// Test cases that simulate real-world usage
	testCases := []struct {
		name           string
		headers        []TemplatedHeader
		accessToken    string
		idToken        string
		claims         map[string]interface{}
		expectedValues map[string]string
	}{
		{
			name: "authorization header with access token",
			headers: []TemplatedHeader{
				{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
			},
			accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedValues: map[string]string{
				"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
		},
		{
			name: "multiple headers with claims",
			headers: []TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-Groups", Value: "{{.Claims.groups}}"},
				{Name: "X-Auth-Token", Value: "{{.AccessToken}}"},
			},
			accessToken: "token123",
			claims: map[string]interface{}{
				"email":  "user@example.com",
				"groups": "admin,developers",
			},
			expectedValues: map[string]string{
				"X-User-Email":  "user@example.com",
				"X-User-Groups": "admin,developers",
				"X-Auth-Token":  "token123",
			},
		},
		{
			name: "complex template expressions",
			headers: []TemplatedHeader{
				{Name: "X-User-Info", Value: "{{.Claims.sub}} ({{.Claims.email}})"},
				{Name: "X-Auth-Header", Value: "Bearer {{.AccessToken}} | ID: {{.IDToken}}"},
			},
			accessToken: "access-token",
			idToken:     "id-token",
			claims: map[string]interface{}{
				"sub":   "user-12345",
				"email": "john@example.com",
			},
			expectedValues: map[string]string{
				"X-User-Info":   "user-12345 (john@example.com)",
				"X-Auth-Header": "Bearer access-token | ID: id-token",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse all templates
			headerTemplates := make(map[string]*template.Template)
			for _, header := range tc.headers {
				tmpl, err := template.New(header.Name).Parse(header.Value)
				if err != nil {
					t.Fatalf("Failed to parse template for %s: %v", header.Name, err)
				}
				headerTemplates[header.Name] = tmpl
			}

			// Create template data (simulating what the middleware does)
			templateData := map[string]interface{}{
				"AccessToken":  tc.accessToken,
				"IDToken":      tc.idToken,
				"RefreshToken": "refresh-token", // Default value
				"Claims":       tc.claims,
			}

			// Create a test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Execute templates and set headers
			for headerName, tmpl := range headerTemplates {
				var buf bytes.Buffer
				err := tmpl.Execute(&buf, templateData)
				if err != nil {
					t.Fatalf("Failed to execute template for %s: %v", headerName, err)
				}
				req.Header.Set(headerName, buf.String())
			}

			// Verify all expected headers are set correctly
			for headerName, expectedValue := range tc.expectedValues {
				actualValue := req.Header.Get(headerName)
				if actualValue != expectedValue {
					t.Errorf("Header %s: expected %q, got %q", headerName, expectedValue, actualValue)
				}
			}
		})
	}
}

// TestIssue55JSONConfigParsing tests that JSON configuration with wrong types
// is properly rejected to prevent the boolean type error
func TestIssue55JSONConfigParsing(t *testing.T) {
	testCases := []struct {
		name          string
		jsonConfig    string
		expectedError bool
		description   string
	}{
		{
			name: "valid JSON configuration",
			jsonConfig: `{
				"headers": [
					{
						"name": "Authorization",
						"value": "Bearer {{.AccessToken}}"
					}
				]
			}`,
			expectedError: false,
			description:   "Properly formatted JSON with string values",
		},
		{
			name: "JSON with boolean value",
			jsonConfig: `{
				"headers": [
					{
						"name": "Authorization",
						"value": true
					}
				]
			}`,
			expectedError: true,
			description:   "Boolean value instead of string template",
		},
		{
			name: "JSON with number value",
			jsonConfig: `{
				"headers": [
					{
						"name": "Authorization",
						"value": 123
					}
				]
			}`,
			expectedError: true,
			description:   "Number value instead of string template",
		},
		{
			name: "JSON with null value",
			jsonConfig: `{
				"headers": [
					{
						"name": "Authorization",
						"value": null
					}
				]
			}`,
			expectedError: false, // JSON unmarshaling null to string results in empty string
			description:   "Null value instead of string template",
		},
		{
			name: "JSON with array value",
			jsonConfig: `{
				"headers": [
					{
						"name": "Authorization",
						"value": ["Bearer", "{{.AccessToken}}"]
					}
				]
			}`,
			expectedError: true,
			description:   "Array value instead of string template",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var config struct {
				Headers []TemplatedHeader `json:"headers"`
			}

			err := json.Unmarshal([]byte(tc.jsonConfig), &config)

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error for %s, but parsing succeeded", tc.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.description, err)
				}
			}
		})
	}
}

// TestIssue55RegressionScenario tests the exact scenario that would cause
// the "can't evaluate field AccessToken in type bool" error
func TestIssue55RegressionScenario(t *testing.T) {
	// This test documents what NOT to do and ensures we catch it
	t.Run("direct boolean context execution", func(t *testing.T) {
		tmpl, err := template.New("test").Parse("{{.AccessToken}}")
		if err != nil {
			t.Fatalf("Failed to parse template: %v", err)
		}

		var buf bytes.Buffer
		// This is what would cause the issue - passing a boolean as template data
		err = tmpl.Execute(&buf, true)

		if err == nil {
			t.Fatalf("Expected error when executing template with boolean context")
		}

		expectedError := "can't evaluate field AccessToken in type bool"
		if !strings.Contains(err.Error(), expectedError) {
			t.Errorf("Expected error containing %q, got %q", expectedError, err.Error())
		}
	})

	t.Run("correct map context execution", func(t *testing.T) {
		tmpl, err := template.New("test").Parse("{{.AccessToken}}")
		if err != nil {
			t.Fatalf("Failed to parse template: %v", err)
		}

		var buf bytes.Buffer
		// This is the correct way - passing a map with the expected fields
		err = tmpl.Execute(&buf, map[string]interface{}{
			"AccessToken": "test-token",
		})

		if err != nil {
			t.Fatalf("Unexpected error with correct template data: %v", err)
		}

		if buf.String() != "test-token" {
			t.Errorf("Expected 'test-token', got %q", buf.String())
		}
	})
}
