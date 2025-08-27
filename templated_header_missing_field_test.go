package traefikoidc

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTemplatedHeaderMissingField tests that accessing non-existent claim fields doesn't cause panics (issue #60)
func TestTemplatedHeaderMissingField(t *testing.T) {
	t.Run("Missing_Claim_Field_Returns_Empty", func(t *testing.T) {
		// Create a template with the missingkey=zero option
		funcMap := template.FuncMap{
			"default": func(defaultVal interface{}, val interface{}) interface{} {
				if val == nil || val == "" {
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

		tmpl := template.New("test").Funcs(funcMap).Option("missingkey=zero")
		parsed, err := tmpl.Parse("{{.Claims.internal_role}}")
		require.NoError(t, err)

		// Create template data with claims that don't have internal_role
		claims := map[string]interface{}{
			"email": "user@example.com",
			"sub":   "1234567890",
			"name":  "John Doe",
			// Note: internal_role is NOT present
		}

		templateData := map[string]interface{}{
			"Claims": claims,
		}

		// Execute template - should not panic
		var buf bytes.Buffer
		err = parsed.Execute(&buf, templateData)
		require.NoError(t, err, "Template execution should not fail for missing field")

		// Should return empty string for missing field with missingkey=zero
		assert.Equal(t, "<no value>", buf.String(), "Missing field should return <no value>")
	})

	t.Run("Safe_Access_Pattern_For_Nested_Fields", func(t *testing.T) {
		funcMap := template.FuncMap{
			"get": func(m interface{}, key string) interface{} {
				if mapVal, ok := m.(map[string]interface{}); ok {
					if val, exists := mapVal[key]; exists {
						return val
					}
				}
				return ""
			},
		}

		tmpl := template.New("test").Funcs(funcMap)
		// Use 'with' to safely check if field exists before accessing nested properties
		parsed, err := tmpl.Parse(`{{with .Claims.groups}}{{.admin}}{{end}}`)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"email": "user@example.com",
			// groups field doesn't exist
		}

		templateData := map[string]interface{}{
			"Claims": claims,
		}

		var buf bytes.Buffer
		err = parsed.Execute(&buf, templateData)
		require.NoError(t, err, "Should handle nested missing fields with 'with' construct")
		assert.Equal(t, "", buf.String(), "Should return empty string when field doesn't exist")
	})

	t.Run("Using_Get_Function_For_Safe_Access", func(t *testing.T) {
		funcMap := template.FuncMap{
			"get": func(m interface{}, key string) interface{} {
				if mapVal, ok := m.(map[string]interface{}); ok {
					if val, exists := mapVal[key]; exists {
						return val
					}
				}
				return ""
			},
		}

		tmpl := template.New("test").Funcs(funcMap)
		// Use the get function to safely access the field
		parsed, err := tmpl.Parse(`{{get .Claims "internal_role"}}`)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"email": "user@example.com",
			// internal_role not present
		}

		templateData := map[string]interface{}{
			"Claims": claims,
		}

		var buf bytes.Buffer
		err = parsed.Execute(&buf, templateData)
		require.NoError(t, err)
		assert.Equal(t, "", buf.String(), "get function should return empty string for missing field")
	})

	t.Run("Using_Default_Function_For_Fallback", func(t *testing.T) {
		funcMap := template.FuncMap{
			"default": func(defaultVal interface{}, val interface{}) interface{} {
				if val == nil || val == "" || val == "<no value>" {
					return defaultVal
				}
				return val
			},
		}

		tmpl := template.New("test").Funcs(funcMap).Option("missingkey=zero")
		// Use default to provide a fallback value
		parsed, err := tmpl.Parse(`{{default "guest" .Claims.role}}`)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"email": "user@example.com",
			// role not present
		}

		templateData := map[string]interface{}{
			"Claims": claims,
		}

		var buf bytes.Buffer
		err = parsed.Execute(&buf, templateData)
		require.NoError(t, err)
		assert.Equal(t, "guest", buf.String(), "default function should provide fallback value")
	})

	t.Run("Existing_Field_Still_Works", func(t *testing.T) {
		funcMap := template.FuncMap{
			"get": func(m interface{}, key string) interface{} {
				if mapVal, ok := m.(map[string]interface{}); ok {
					if val, exists := mapVal[key]; exists {
						return val
					}
				}
				return ""
			},
		}

		tmpl := template.New("test").Funcs(funcMap).Option("missingkey=zero")
		parsed, err := tmpl.Parse("{{.Claims.email}}")
		require.NoError(t, err)

		claims := map[string]interface{}{
			"email": "user@example.com",
			"role":  "admin",
		}

		templateData := map[string]interface{}{
			"Claims": claims,
		}

		var buf bytes.Buffer
		err = parsed.Execute(&buf, templateData)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", buf.String(), "Existing fields should work normally")
	})
}

// TestHeaderTemplateIntegration tests the full integration of templated headers
func TestHeaderTemplateIntegration(t *testing.T) {
	t.Run("Headers_With_Missing_Claims_Dont_Crash", func(t *testing.T) {
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// Add headers that reference potentially missing fields
		config.Headers = []TemplatedHeader{
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-User-Role", Value: "{{.Claims.internal_role}}"}, // This field might not exist
			{Name: "X-User-Groups", Value: "{{.Claims.groups}}"},      // This field might not exist
		}

		// We can't fully initialize the plugin without network access,
		// but we can test that the configuration validates
		err := config.Validate()
		assert.NoError(t, err, "Configuration should be valid even with potentially missing fields")
	})
}
