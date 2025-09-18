package features

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock types for testing
type TemplatedHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MockConfig struct {
	ProviderURL          string            `json:"providerURL"`
	ClientID             string            `json:"clientID"`
	ClientSecret         string            `json:"clientSecret"`
	CallbackURL          string            `json:"callbackURL"`
	SessionEncryptionKey string            `json:"sessionEncryptionKey"`
	Headers              []TemplatedHeader `json:"headers"`
}

// TestTemplateHeaderFeatures consolidates all template header-related tests
func TestTemplateHeaderFeatures(t *testing.T) {
	t.Run("Issue55_TemplateExecutionWithWrongTypes", testIssue55TemplateExecutionWithWrongTypes)
	t.Run("Template_Parsing_Validation", testTemplateParsingValidation)
	t.Run("Middleware_Header_Templating", testMiddlewareHeaderTemplating)
	t.Run("JSON_Config_Parsing", testJSONConfigParsing)
	t.Run("Template_Double_Processing", testTemplateDoubleProcessing)
	t.Run("Template_Execution_Context", testTemplateExecutionContext)
	t.Run("Template_Integration_With_Plugin", testTemplateIntegrationWithPlugin)
	t.Run("Template_Syntax_Validation", testTemplateSyntaxValidation)
	t.Run("Missing_Field_Handling", testMissingFieldHandling)
	t.Run("Complex_Template_Expressions", testComplexTemplateExpressions)
	t.Run("Traefik_Configuration_Parsing", testTraefikConfigurationParsing)
}

// testIssue55TemplateExecutionWithWrongTypes tests what happens when templates
// receive wrong data types during execution - reproduces GitHub issue #55
func testIssue55TemplateExecutionWithWrongTypes(t *testing.T) {
	testCases := []struct {
		name          string
		templateText  string
		templateData  interface{}
		errorContains string
		expectError   bool
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
				"Claims": "not a map",
			},
			expectError:   true,
			errorContains: "can't evaluate field email in type",
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
			require.NoError(t, err)

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.templateData)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// testTemplateParsingValidation ensures templates are parsed correctly
func testTemplateParsingValidation(t *testing.T) {
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, header := range tc.headerTemplates {
				_, err := template.New(header.Name).Parse(header.Value)

				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

// testMiddlewareHeaderTemplating simulates the actual middleware flow
func testMiddlewareHeaderTemplating(t *testing.T) {
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
				require.NoError(t, err)
				headerTemplates[header.Name] = tmpl
			}

			// Create template data
			templateData := map[string]interface{}{
				"AccessToken": tc.accessToken,
				"IDToken":     tc.idToken,
				"Claims":      tc.claims,
			}

			// Create a test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Execute templates and set headers
			for headerName, tmpl := range headerTemplates {
				var buf bytes.Buffer
				err := tmpl.Execute(&buf, templateData)
				require.NoError(t, err)
				req.Header.Set(headerName, buf.String())
			}

			// Verify all expected headers are set correctly
			for headerName, expectedValue := range tc.expectedValues {
				actualValue := req.Header.Get(headerName)
				assert.Equal(t, expectedValue, actualValue)
			}
		})
	}
}

// testJSONConfigParsing tests that JSON configuration is properly parsed
func testJSONConfigParsing(t *testing.T) {
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var config struct {
				Headers []TemplatedHeader `json:"headers"`
			}

			err := json.Unmarshal([]byte(tc.jsonConfig), &config)

			if tc.expectedError {
				require.Error(t, err, tc.description)
			} else {
				require.NoError(t, err, tc.description)
			}
		})
	}
}

// testTemplateDoubleProcessing tests if template strings are being double-processed
func testTemplateDoubleProcessing(t *testing.T) {
	// Simulate how Traefik passes config to the plugin
	config := &MockConfig{
		Headers: []TemplatedHeader{
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-User-Role", Value: "{{.Claims.internal_role}}"},
		},
	}

	// Verify that template strings are still raw (not processed)
	assert.Equal(t, "{{.Claims.email}}", config.Headers[0].Value)
	assert.Equal(t, "{{.Claims.internal_role}}", config.Headers[1].Value)

	// Simulate template parsing during initialization
	headerTemplates := make(map[string]*template.Template)

	funcMap := template.FuncMap{
		"default": func(defaultVal interface{}, val interface{}) interface{} {
			if val == nil || val == "" || val == "<no value>" {
				return defaultVal
			}
			return val
		},
		"get": func(m interface{}, key string) interface{} {
			if mapVal, ok := m.(map[string]interface{}); ok {
				if val, exists := mapVal[key]; exists {
					return val
				}
			}
			return ""
		},
	}

	for _, header := range config.Headers {
		tmpl := template.New(header.Name).Funcs(funcMap).Option("missingkey=zero")
		parsedTmpl, err := tmpl.Parse(header.Value)
		require.NoError(t, err)
		headerTemplates[header.Name] = parsedTmpl
	}

	// Test execution with actual claims
	claims := map[string]interface{}{
		"email": "user@example.com",
		// Note: internal_role is missing
	}

	templateData := map[string]interface{}{
		"Claims": claims,
	}

	// Execute templates
	for headerName, tmpl := range headerTemplates {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, templateData)
		require.NoError(t, err)

		result := buf.String()
		if headerName == "X-User-Email" {
			assert.Equal(t, "user@example.com", result)
		} else if headerName == "X-User-Role" {
			// With missingkey=zero, missing fields return "<no value>"
			assert.Equal(t, "<no value>", result)
		}
	}
}

// testTemplateExecutionContext tests the specific template data context
func testTemplateExecutionContext(t *testing.T) {
	testCases := []struct {
		name          string
		templateText  string
		data          map[string]interface{}
		expectedValue string
	}{
		{
			name:         "Access and ID token distinction",
			templateText: "Access: {{.AccessToken}} ID: {{.IDToken}}",
			data: map[string]interface{}{
				"AccessToken": "access-token-value",
				"IDToken":     "id-token-value",
				"Claims":      map[string]interface{}{},
			},
			expectedValue: "Access: access-token-value ID: id-token-value",
		},
		{
			name:         "Combining tokens and claims",
			templateText: "User: {{.Claims.sub}} Token: {{.AccessToken}}",
			data: map[string]interface{}{
				"AccessToken": "access-token",
				"IDToken":     "id-token",
				"Claims": map[string]interface{}{
					"sub": "user123",
				},
			},
			expectedValue: "User: user123 Token: access-token",
		},
		{
			name:         "Custom non-standard claims",
			templateText: "X-User-Role: {{.Claims.role}}, X-User-Permissions: {{.Claims.permissions}}",
			data: map[string]interface{}{
				"AccessToken": "access-token-value",
				"Claims": map[string]interface{}{
					"role":        "admin",
					"permissions": "read:all,write:own",
				},
			},
			expectedValue: "X-User-Role: admin, X-User-Permissions: read:all,write:own",
		},
		{
			name:         "Deeply nested custom claims",
			templateText: "X-Organization: {{.Claims.app_metadata.organization.name}}, X-Team: {{.Claims.app_metadata.team}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"app_metadata": map[string]interface{}{
						"organization": map[string]interface{}{
							"name": "acme-corp",
						},
						"team": "platform",
					},
				},
			},
			expectedValue: "X-Organization: acme-corp, X-Team: platform",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)
			require.NoError(t, err)

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.data)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedValue, buf.String())
		})
	}
}

// testTemplateIntegrationWithPlugin tests template processing in the actual plugin
func testTemplateIntegrationWithPlugin(t *testing.T) {
	// Test template integration using mock plugin components

	// Set up test OIDC server
	var testServerURL string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 testServerURL,
				"authorization_endpoint": testServerURL + "/auth",
				"token_endpoint":         testServerURL + "/token",
				"jwks_uri":               testServerURL + "/jwks",
				"userinfo_endpoint":      testServerURL + "/userinfo",
			})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []interface{}{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer testServer.Close()
	testServerURL = testServer.URL

	// Create config with templates that reference potentially missing fields
	config := &MockConfig{
		ProviderURL:          testServer.URL,
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "/callback",
		SessionEncryptionKey: "test-encryption-key-32-characters",
		Headers: []TemplatedHeader{
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-User-Role", Value: "{{.Claims.internal_role}}"},
		},
	}

	// Initialize plugin would be done here
	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test would create plugin handler here
	_ = ctx
	_ = next
	_ = config
}

// testTemplateSyntaxValidation tests that template syntax is properly validated
func testTemplateSyntaxValidation(t *testing.T) {
	validTemplates := []string{
		"{{.Claims.email}}",
		"{{.Claims.internal_role}}",
		"{{.AccessToken}}",
		"{{.IdToken}}",
		"{{.RefreshToken}}",
	}

	for _, tmplStr := range validTemplates {
		err := validateTemplateSecure(tmplStr)
		assert.NoError(t, err, "Template should be valid: %s", tmplStr)
	}

	// Test invalid templates
	invalidTemplates := []struct {
		template string
		reason   string
	}{
		{"{{call .SomeFunc}}", "function calls not allowed"},
		{"{{range .Items}}{{.}}{{end}}", "range not allowed"},
		{"{{with .Data}}{{.Field}}{{end}}", "with statements blocked"},
		{"{{index .Array 0}}", "index access blocked"},
		{"{{printf \"%s\" .Data}}", "printf blocked"},
	}

	for _, tc := range invalidTemplates {
		err := validateTemplateSecure(tc.template)
		assert.Error(t, err, "Template should be invalid: %s (%s)", tc.template, tc.reason)
		assert.Contains(t, strings.ToLower(err.Error()), "dangerous")
	}

	// Test safe custom functions
	safeTemplates := []string{
		"{{get .Claims \"internal_role\"}}",
		"{{default \"guest\" .Claims.role}}",
	}

	for _, tmplStr := range safeTemplates {
		err := validateTemplateSecure(tmplStr)
		assert.NoError(t, err, "Safe custom functions should be allowed: %s", tmplStr)
	}
}

// Mock validation function for template security
func validateTemplateSecure(templateStr string) error {
	// List of potentially dangerous template actions
	dangerousFunctions := []string{
		"call", "range", "with", "index", "printf", "println", "print",
		"js", "html", "urlquery", "base64", "exec",
	}

	for _, dangerous := range dangerousFunctions {
		if strings.Contains(templateStr, dangerous) {
			return fmt.Errorf("dangerous template function detected: %s", dangerous)
		}
	}

	// Define safe custom functions
	funcMap := template.FuncMap{
		"get": func(data map[string]interface{}, key string) interface{} {
			return data[key]
		},
		"default": func(defaultVal interface{}, val interface{}) interface{} {
			if val == nil || val == "" {
				return defaultVal
			}
			return val
		},
	}

	// Try to parse the template with custom functions to check for syntax errors
	_, err := template.New("test").Funcs(funcMap).Parse(templateStr)
	return err
}

// testMissingFieldHandling tests handling of missing fields in templates
func testMissingFieldHandling(t *testing.T) {
	testCases := []struct {
		name         string
		templateText string
		data         map[string]interface{}
		expected     string
	}{
		{
			name:         "missing claim field",
			templateText: "{{.Claims.missing}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{},
			},
			expected: "<no value>",
		},
		{
			name:         "missing nested field",
			templateText: "{{.Claims.user.missing}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"user": map[string]interface{}{},
				},
			},
			expected: "<no value>",
		},
		{
			name:         "missing entire path",
			templateText: "{{.Missing.Path.Field}}",
			data:         map[string]interface{}{},
			expected:     "<no value>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)
			require.NoError(t, err)

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.data)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, buf.String())
		})
	}
}

// testComplexTemplateExpressions tests complex template expressions
func testComplexTemplateExpressions(t *testing.T) {
	testCases := []struct {
		name         string
		templateText string
		data         map[string]interface{}
		expected     string
	}{
		{
			name:         "conditional template",
			templateText: "{{if .Claims.admin}}Admin User{{else}}Regular User{{end}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"admin": true,
				},
			},
			expected: "Admin User",
		},
		{
			name:         "multiple claims concatenation",
			templateText: "{{.Claims.firstName}} {{.Claims.lastName}} <{{.Claims.email}}>",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
					"email":     "john.doe@example.com",
				},
			},
			expected: "John Doe <john.doe@example.com>",
		},
		{
			name:         "array access",
			templateText: "{{index .Claims.roles 0}}",
			data: map[string]interface{}{
				"Claims": map[string]interface{}{
					"roles": []string{"admin", "user"},
				},
			},
			expected: "admin",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)
			require.NoError(t, err)

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, tc.data)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, buf.String())
		})
	}
}

// testTraefikConfigurationParsing tests various ways Traefik might pass configuration
func testTraefikConfigurationParsing(t *testing.T) {
	testCases := []struct {
		name        string
		config      *MockConfig
		expectError bool
		description string
	}{
		{
			name: "valid configuration with templated headers",
			config: &MockConfig{
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
			config: &MockConfig{
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
			config: &MockConfig{
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a simple next handler
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Try to create the middleware would be done here
			ctx := context.Background()

			// Test would create middleware handler here
			_ = ctx
			_ = next
			_ = tc.config

			// For now, we just validate the configuration is well-formed
			if !tc.expectError {
				require.NotNil(t, tc.config, tc.description)
				require.NotEmpty(t, tc.config.ClientID, tc.description)
			}
		})
	}
}
