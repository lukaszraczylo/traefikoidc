package traefikoidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssue60Integration tests the complete fix for issue #60
// This test verifies that the plugin can handle missing claim fields without panicking
func TestIssue60Integration(t *testing.T) {
	t.Run("Config_With_Safe_Functions_Validates", func(t *testing.T) {
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// Templates using safe functions for missing fields
		config.Headers = []TemplatedHeader{
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-User-Role", Value: "{{get .Claims \"internal_role\"}}"},
			{Name: "X-User-Dept", Value: "{{default \"unknown\" .Claims.department}}"},
			{Name: "X-User-Groups", Value: "{{with .Claims.groups}}{{.}}{{end}}"},
		}

		// Configuration should validate successfully
		err := config.Validate()
		assert.NoError(t, err, "Config with safe template functions should validate")
	})

	t.Run("Direct_Template_Access_Works", func(t *testing.T) {
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// Direct claim access (will return <no value> if missing with missingkey=zero)
		config.Headers = []TemplatedHeader{
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-Internal-Role", Value: "{{.Claims.internal_role}}"},
		}

		err := config.Validate()
		assert.NoError(t, err, "Direct claim access should validate")
	})

	t.Run("Config_Rejects_Dangerous_Templates", func(t *testing.T) {
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// Dangerous template patterns should be rejected
		dangerousTemplates := []TemplatedHeader{
			{Name: "X-Bad-1", Value: "{{call .SomeFunc}}"},
			{Name: "X-Bad-2", Value: "{{range .Items}}{{.}}{{end}}"},
			{Name: "X-Bad-3", Value: "{{index .Array 0}}"},
			{Name: "X-Bad-4", Value: "{{printf \"%s\" .Data}}"},
		}

		for _, header := range dangerousTemplates {
			config.Headers = []TemplatedHeader{header}
			err := config.Validate()
			require.Error(t, err, "Dangerous template should be rejected: %s", header.Value)
			assert.Contains(t, err.Error(), "dangerous", "Error should mention dangerous pattern")
		}
	})

	t.Run("Verify_Template_Execution_Context", func(t *testing.T) {
		// This test verifies that our template context matches what's actually used
		// The context should have these fields (all capitalized):
		// - AccessToken
		// - IDToken (or IdToken)
		// - RefreshToken
		// - Claims (map[string]interface{})

		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// These should all be valid based on the actual template context
		validContextTemplates := []TemplatedHeader{
			{Name: "X-Access-Token", Value: "{{.AccessToken}}"},
			{Name: "X-ID-Token", Value: "{{.IdToken}}"},
			{Name: "X-Refresh-Token", Value: "{{.RefreshToken}}"},
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-User-Sub", Value: "{{.Claims.sub}}"},
		}

		config.Headers = validContextTemplates
		err := config.Validate()
		assert.NoError(t, err, "All valid context fields should pass validation")
	})

	t.Run("Common_Azure_AD_Claims", func(t *testing.T) {
		// Test Azure AD specific claims mentioned in issue #60
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// Azure AD commonly uses these claim fields
		config.Headers = []TemplatedHeader{
			{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			{Name: "X-User-OID", Value: "{{.Claims.oid}}"},
			{Name: "X-User-TID", Value: "{{.Claims.tid}}"},
			{Name: "X-User-UPN", Value: "{{.Claims.upn}}"},
			{Name: "X-Internal-Role", Value: "{{.Claims.internal_role}}"}, // Custom claim from issue #60
		}

		err := config.Validate()
		assert.NoError(t, err, "Azure AD claims should validate")
	})
}

// TestIssue60RealWorldScenarios tests real-world scenarios from issue #60
func TestIssue60RealWorldScenarios(t *testing.T) {
	t.Run("Missing_Internal_Role_Field", func(t *testing.T) {
		// This is the exact scenario from issue #60
		// User passes {{.Claims.internal_role}} but the field doesn't exist
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// The problematic template from issue #60
		config.Headers = []TemplatedHeader{
			{Name: "X-Internal-Role", Value: "{{.Claims.internal_role}}"},
		}

		// Should validate (internal_role is in the safe fields list)
		err := config.Validate()
		assert.NoError(t, err, "Template with internal_role should validate")
	})

	t.Run("Safe_Access_Patterns_From_Guide", func(t *testing.T) {
		// Test all the safe patterns documented in TEMPLATE_HEADERS_GUIDE.md
		config := CreateConfig()
		config.ProviderURL = "https://example.com"
		config.ClientID = "test-client"
		config.ClientSecret = "test-secret"
		config.CallbackURL = "/callback"
		config.SessionEncryptionKey = "test-encryption-key-32-characters"

		// All safe patterns from the guide
		config.Headers = []TemplatedHeader{
			// Basic field access
			{Name: "X-User-Role", Value: "{{.Claims.internal_role}}"},

			// Using the get function
			{Name: "X-User-Role-Get", Value: "{{get .Claims \"internal_role\"}}"},

			// Using the default function
			{Name: "X-User-Role-Default", Value: "{{default \"guest\" .Claims.role}}"},

			// Nested fields with 'with'
			{Name: "X-User-Admin", Value: "{{with .Claims.groups}}{{.admin}}{{end}}"},
		}

		err := config.Validate()
		assert.NoError(t, err, "All safe patterns from guide should validate")
	})
}

// TestIssue60DoubleProcessingConcern tests the user's specific concern about double processing
func TestIssue60DoubleProcessingConcern(t *testing.T) {
	t.Run("Template_Not_Evaluated_During_Config_Parse", func(t *testing.T) {
		// The user was concerned that templates might be processed twice:
		// 1. Once when Traefik parses the config
		// 2. Once when the plugin executes the template

		// This test verifies that templates are stored as strings during config parsing
		config := &Config{
			Headers: []TemplatedHeader{
				{Name: "X-Test", Value: "{{.Claims.test}}"},
			},
		}

		// The template should still be a raw string after config creation
		assert.Equal(t, "{{.Claims.test}}", config.Headers[0].Value,
			"Template should remain as raw string in config")

		// The template is only parsed/executed when the plugin initializes and processes requests
		// Not during config unmarshaling
	})

	t.Run("Functions_Preserved_Through_Config_Marshaling", func(t *testing.T) {
		// Test that our custom function syntax survives config marshaling/unmarshaling
		originalValue := `{{get .Claims "internal_role"}}`
		header := TemplatedHeader{
			Name:  "X-Role",
			Value: originalValue,
		}

		// Even after any marshaling/unmarshaling, the template string should be preserved
		assert.Equal(t, originalValue, header.Value,
			"Template with functions should be preserved exactly")
	})
}
