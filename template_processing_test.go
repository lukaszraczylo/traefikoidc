package traefikoidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTemplateDoubleProcessing tests if template strings are being double-processed
// This addresses the user's concern about potential double processing by the parser
func TestTemplateDoubleProcessing(t *testing.T) {
	t.Run("Template_Strings_Not_Double_Processed", func(t *testing.T) {
		// Simulate how Traefik passes config to the plugin
		// Traefik uses YAML/TOML config which gets unmarshaled into the Config struct
		// yamlConfig example:
		// headers:
		//   - name: "X-User-Email"
		//     value: "{{.Claims.email}}"
		//   - name: "X-User-Role"
		//     value: "{{.Claims.internal_role}}"

		// This simulates what Traefik does internally - it parses YAML/TOML and creates a Config struct
		// The template strings are NOT processed at this stage, they're just strings
		config := &Config{
			Headers: []TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-Role", Value: "{{.Claims.internal_role}}"},
			},
		}

		// Verify that template strings are still raw (not processed)
		assert.Equal(t, "{{.Claims.email}}", config.Headers[0].Value)
		assert.Equal(t, "{{.Claims.internal_role}}", config.Headers[1].Value)

		// Now simulate what happens when the plugin initializes
		// The template strings should only be parsed once during initialization
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
	})

	t.Run("Config_Marshaling_Preserves_Template_Syntax", func(t *testing.T) {
		// Test that marshaling/unmarshaling config doesn't affect template strings
		originalConfig := &Config{
			ProviderURL:          "https://example.com",
			ClientID:             "test-client",
			ClientSecret:         "test-secret",
			CallbackURL:          "/callback",
			SessionEncryptionKey: "test-encryption-key-32-characters",
			Headers: []TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-Role", Value: "{{get .Claims \"internal_role\"}}"},
				{Name: "X-User-Dept", Value: "{{default \"unknown\" .Claims.department}}"},
			},
		}

		// Marshal to JSON (simulating Traefik's config processing)
		jsonData, err := json.Marshal(originalConfig)
		require.NoError(t, err)

		// Unmarshal back
		var unmarshaledConfig Config
		err = json.Unmarshal(jsonData, &unmarshaledConfig)
		require.NoError(t, err)

		// Verify template strings are preserved exactly
		assert.Equal(t, "{{.Claims.email}}", unmarshaledConfig.Headers[0].Value)
		assert.Equal(t, `{{get .Claims "internal_role"}}`, unmarshaledConfig.Headers[1].Value)
		assert.Equal(t, `{{default "unknown" .Claims.department}}`, unmarshaledConfig.Headers[2].Value)
	})

	t.Run("Template_Functions_Work_After_Config_Processing", func(t *testing.T) {
		// Simulate the full flow from config to execution
		jsonConfig := `{
			"providerURL": "https://example.com",
			"clientID": "test-client",
			"clientSecret": "test-secret",
			"callbackURL": "/callback",
			"sessionEncryptionKey": "test-encryption-key-32-characters",
			"headers": [
				{"name": "X-User-Email", "value": "{{.Claims.email}}"},
				{"name": "X-User-Role", "value": "{{get .Claims \"internal_role\"}}"},
				{"name": "X-User-Dept", "value": "{{default \"engineering\" .Claims.department}}"}
			]
		}`

		var config Config
		err := json.Unmarshal([]byte(jsonConfig), &config)
		require.NoError(t, err)

		// Initialize templates with functions
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

		headerTemplates := make(map[string]*template.Template)
		for _, header := range config.Headers {
			tmpl := template.New(header.Name).Funcs(funcMap).Option("missingkey=zero")
			parsedTmpl, err := tmpl.Parse(header.Value)
			require.NoError(t, err)
			headerTemplates[header.Name] = parsedTmpl
		}

		// Test with claims
		claims := map[string]interface{}{
			"email": "user@example.com",
			// internal_role and department are missing
		}

		templateData := map[string]interface{}{
			"Claims": claims,
		}

		results := make(map[string]string)
		for headerName, tmpl := range headerTemplates {
			var buf bytes.Buffer
			err := tmpl.Execute(&buf, templateData)
			require.NoError(t, err)
			results[headerName] = buf.String()
		}

		// Verify results
		assert.Equal(t, "user@example.com", results["X-User-Email"])
		assert.Equal(t, "", results["X-User-Role"])            // get function returns empty string
		assert.Equal(t, "engineering", results["X-User-Dept"]) // default function provides fallback
	})
}

// TestTemplateIntegrationWithPlugin tests template processing in the actual plugin
func TestTemplateIntegrationWithPlugin(t *testing.T) {
	t.Run("Plugin_Handles_Missing_Claims_Safely", func(t *testing.T) {
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
		config := &Config{
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

		// Initialize plugin
		ctx := context.Background()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check headers set by the plugin
			email := r.Header.Get("X-User-Email")
			role := r.Header.Get("X-User-Role")

			// Write headers to response for testing
			w.Header().Set("X-Test-Email", email)
			w.Header().Set("X-Test-Role", role)
			w.WriteHeader(http.StatusOK)
		})

		handler, err := New(ctx, next, config, "test-plugin")
		require.NoError(t, err)

		traefikOidc, ok := handler.(*TraefikOidc)
		require.True(t, ok)

		// Create a mock session with claims
		req := httptest.NewRequest("GET", "/protected", nil)

		// Create session and set authentication
		session, err := traefikOidc.sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set authentication with minimal claims (missing internal_role)
		session.SetAuthenticated(true)
		session.SetEmail("user@example.com")

		// Create ID token with limited claims
		claims := map[string]interface{}{
			"email": "user@example.com",
			"sub":   "user123",
			// internal_role is missing
		}

		// Create a simple test JWT (signature verification is mocked in tests)
		idToken, _ := createTestJWT(nil, "test-issuer", "test-client", claims)
		session.SetIDToken(idToken)

		// Save session
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Create new request with session cookie
		cookies := rec.Result().Cookies()
		req2 := httptest.NewRequest("GET", "/protected", nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		// Process request through plugin
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)

		// Plugin should handle missing claims gracefully
		// The request should proceed without errors
		assert.NotEqual(t, http.StatusInternalServerError, rec2.Code)
	})
}

// Removed createTestJWT as it already exists in main_test.go

// TestTemplateSyntaxValidation tests that template syntax is properly validated
func TestTemplateSyntaxValidation(t *testing.T) {
	t.Run("Valid_Template_Syntax", func(t *testing.T) {
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
	})

	t.Run("Invalid_Template_Syntax_Blocked", func(t *testing.T) {
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
	})

	t.Run("Template_With_Custom_Functions", func(t *testing.T) {
		// These templates use our safe custom functions which are now allowed
		templates := []string{
			"{{get .Claims \"internal_role\"}}",
			"{{default \"guest\" .Claims.role}}",
		}

		// These safe custom functions should now be allowed
		for _, tmplStr := range templates {
			err := validateTemplateSecure(tmplStr)
			assert.NoError(t, err, "Safe custom functions should be allowed: %s", tmplStr)
		}

		// But other function calls should still be blocked
		dangerousFunctions := []string{
			"{{call .SomeFunc}}",
			"{{index .Array 0}}",
			"{{slice .Data 0 10}}",
		}

		for _, tmplStr := range dangerousFunctions {
			err := validateTemplateSecure(tmplStr)
			assert.Error(t, err, "Dangerous function calls should still be blocked: %s", tmplStr)
		}
	})
}
