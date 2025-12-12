package providers

import (
	"fmt"
	"strings"
)

// ProviderWarning represents a warning about provider limitations or requirements.
type ProviderWarning struct {
	Level        string
	Message      string
	ProviderType ProviderType
}

// GetProviderWarnings returns warnings about provider-specific limitations.
func GetProviderWarnings(providerType ProviderType) []ProviderWarning {
	var warnings []ProviderWarning

	switch providerType {
	case ProviderTypeGitHub:
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeGitHub,
			Level:        "warning",
			Message:      "GitHub uses OAuth 2.0, not OpenID Connect. ID tokens are not available. Use access tokens for API calls only.",
		})
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeGitHub,
			Level:        "info",
			Message:      "GitHub OAuth apps do not support refresh tokens. Users will need to re-authenticate when tokens expire.",
		})

	case ProviderTypeAuth0:
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeAuth0,
			Level:        "info",
			Message:      "Auth0 requires 'offline_access' scope for refresh tokens. This will be automatically added.",
		})

	case ProviderTypeOkta:
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeOkta,
			Level:        "info",
			Message:      "Okta requires proper application configuration in your Okta admin console for OIDC to work.",
		})

	case ProviderTypeKeycloak:
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeKeycloak,
			Level:        "info",
			Message:      "Keycloak detection is based on URL path '/auth/realms/'. Ensure your issuer URL follows this pattern.",
		})

	case ProviderTypeAWSCognito:
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeAWSCognito,
			Level:        "info",
			Message:      "AWS Cognito uses regional endpoints. Ensure your issuer URL includes the correct region (e.g., cognito-idp.us-east-1.amazonaws.com).",
		})

	case ProviderTypeGitLab:
		warnings = append(warnings, ProviderWarning{
			ProviderType: ProviderTypeGitLab,
			Level:        "info",
			Message:      "GitLab supports OIDC but requires application registration in GitLab admin settings.",
		})
	}

	return warnings
}

// ValidateProviderCompatibility checks if a provider is suitable for OIDC authentication.
func ValidateProviderCompatibility(providerType ProviderType, requiresOIDC bool) error {
	switch providerType {
	case ProviderTypeGitHub:
		if requiresOIDC {
			return fmt.Errorf("GitHub does not support OpenID Connect. It only supports OAuth 2.0. Consider using a different provider for OIDC authentication")
		}
		return nil
	default:
		return nil
	}
}

// GetProviderRecommendations returns setup recommendations for each provider.
func GetProviderRecommendations(providerType ProviderType) []string {
	switch providerType {
	case ProviderTypeGitHub:
		return []string{
			"Register an OAuth App in GitHub Settings > Developer settings > OAuth Apps",
			"Use scopes: 'user:email', 'read:user' for basic profile access",
			"GitHub tokens expire, plan for re-authentication flow",
		}

	case ProviderTypeAuth0:
		return []string{
			"Create an Application in Auth0 Dashboard",
			"Set Application Type to 'Regular Web Application'",
			"Configure Allowed Callback URLs with your redirect URI",
			"Enable 'offline_access' scope for refresh tokens",
		}

	case ProviderTypeOkta:
		return []string{
			"Create an App Integration in Okta Admin Console",
			"Choose 'OIDC - OpenID Connect' as sign-in method",
			"Select 'Web Application' as application type",
			"Configure redirect URIs and assign users/groups",
		}

	case ProviderTypeKeycloak:
		return []string{
			"Create a Client in your Keycloak realm",
			"Set Client Protocol to 'openid-connect'",
			"Configure Valid Redirect URIs",
			"Ensure issuer URL format: https://your-keycloak/auth/realms/your-realm",
		}

	case ProviderTypeAWSCognito:
		return []string{
			"Create a User Pool in AWS Cognito",
			"Create an App Client with 'Authorization code grant' enabled",
			"Configure App Client settings and callback URLs",
			"Use issuer URL format: https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
		}

	case ProviderTypeGitLab:
		return []string{
			"Create an Application in GitLab (Admin Area > Applications)",
			"Select 'openid', 'profile', 'email' scopes",
			"Configure Redirect URI",
			"Use issuer URL: https://gitlab.com (for GitLab.com)",
		}

	default:
		return []string{}
	}
}

// FormatProviderWarnings formats warnings for display.
func FormatProviderWarnings(warnings []ProviderWarning) string {
	if len(warnings) == 0 {
		return ""
	}

	var result strings.Builder
	for _, warning := range warnings {
		result.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(warning.Level), warning.Message))
	}

	return result.String()
}
