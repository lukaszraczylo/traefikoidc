package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/lukaszraczylo/traefikoidc"
	"gopkg.in/yaml.v3"
)

// Config is the top-level oidcgate configuration. The OIDC subtree maps 1:1
// onto traefikoidc.Config; the few extra fields configure the daemon itself.
type Config struct {
	Listen    string             `json:"listen"`
	AuthPath  string             `json:"authPath"`
	StartPath string             `json:"startPath"`
	OIDC      traefikoidc.Config `json:"-"`
}

// envScalarFields lists Config field names (within OIDC and top-level)
// that may be overridden via OIDCGATE_<UPPER_SNAKE_CASE> environment
// variables. Only scalar strings/ints/bools are supported; nested structs
// (Redis, SecurityHeaders, DynamicClientRegistration) stay YAML-only.
var envScalarFields = []string{
	"Listen", "AuthPath", "StartPath",
	"ProviderURL", "ClientID", "ClientSecret", "Audience",
	"CallbackURL", "LogoutURL", "PostLogoutRedirectURI",
	"SessionEncryptionKey", "CookiePrefix", "CookieDomain",
	"LogLevel", "RevocationURL", "OIDCEndSessionURL",
	"UserIdentifierClaim", "GroupClaimName", "RoleClaimName",
	"ClientAuthMethod", "ClientAssertionPrivateKey",
	"ClientAssertionKeyPath", "ClientAssertionKeyID", "ClientAssertionAlg",
	"CACertPath", "CACertPEM",
}

// Load reads YAML from path, applies env-var overrides, fills defaults,
// and forces TrustForwardedURI=true so the library honors X-Forwarded-Uri.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is a trusted operator-supplied config file path
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Pass 1: YAML → generic map.
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}

	// Split the top-level oidcgate-specific keys away from the OIDC subtree.
	listen, _ := raw["listen"].(string)
	authPath, _ := raw["authPath"].(string)
	startPath, _ := raw["startPath"].(string)
	delete(raw, "listen")
	delete(raw, "authPath")
	delete(raw, "startPath")

	// Pass 2: remaining map → JSON → traefikoidc.Config (uses existing json tags).
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("yaml→json: %w", err)
	}
	var oidcCfg traefikoidc.Config
	if err := json.Unmarshal(jsonBytes, &oidcCfg); err != nil {
		return nil, fmt.Errorf("oidc config parse: %w", err)
	}

	cfg := &Config{
		Listen:    listen,
		AuthPath:  authPath,
		StartPath: startPath,
		OIDC:      oidcCfg,
	}

	applyEnvOverrides(cfg)
	applyDefaults(cfg)

	if cfg.Listen == "" {
		return nil, fmt.Errorf("config: missing required 'listen' (or OIDCGATE_LISTEN env var)")
	}

	// Force standalone semantics: trust X-Forwarded-Uri.
	cfg.OIDC.TrustForwardedURI = true
	return cfg, nil
}

// applyEnvOverrides walks the allow-listed scalar fields and replaces any
// non-empty OIDCGATE_<UPPER_SNAKE_CASE> env var. Field name "ClientID"
// becomes "OIDCGATE_CLIENT_ID"; "SessionEncryptionKey" becomes
// "OIDCGATE_SESSION_ENCRYPTION_KEY".
func applyEnvOverrides(cfg *Config) {
	for _, field := range envScalarFields {
		env := os.Getenv("OIDCGATE_" + camelToSnakeUpper(field))
		if env == "" {
			continue
		}
		setScalarField(cfg, field, env)
	}
}

func setScalarField(cfg *Config, field, value string) {
	switch field {
	case "Listen":
		cfg.Listen = value
	case "AuthPath":
		cfg.AuthPath = value
	case "StartPath":
		cfg.StartPath = value
	case "ProviderURL":
		cfg.OIDC.ProviderURL = value
	case "ClientID":
		cfg.OIDC.ClientID = value
	case "ClientSecret":
		cfg.OIDC.ClientSecret = value
	case "Audience":
		cfg.OIDC.Audience = value
	case "CallbackURL":
		cfg.OIDC.CallbackURL = value
	case "LogoutURL":
		cfg.OIDC.LogoutURL = value
	case "PostLogoutRedirectURI":
		cfg.OIDC.PostLogoutRedirectURI = value
	case "SessionEncryptionKey":
		cfg.OIDC.SessionEncryptionKey = value
	case "CookiePrefix":
		cfg.OIDC.CookiePrefix = value
	case "CookieDomain":
		cfg.OIDC.CookieDomain = value
	case "LogLevel":
		cfg.OIDC.LogLevel = value
	case "RevocationURL":
		cfg.OIDC.RevocationURL = value
	case "OIDCEndSessionURL":
		cfg.OIDC.OIDCEndSessionURL = value
	case "UserIdentifierClaim":
		cfg.OIDC.UserIdentifierClaim = value
	case "GroupClaimName":
		cfg.OIDC.GroupClaimName = value
	case "RoleClaimName":
		cfg.OIDC.RoleClaimName = value
	case "ClientAuthMethod":
		cfg.OIDC.ClientAuthMethod = value
	case "ClientAssertionPrivateKey":
		cfg.OIDC.ClientAssertionPrivateKey = value
	case "ClientAssertionKeyPath":
		cfg.OIDC.ClientAssertionKeyPath = value
	case "ClientAssertionKeyID":
		cfg.OIDC.ClientAssertionKeyID = value
	case "ClientAssertionAlg":
		cfg.OIDC.ClientAssertionAlg = value
	case "CACertPath":
		cfg.OIDC.CACertPath = value
	case "CACertPEM":
		cfg.OIDC.CACertPEM = value
	}
}

func applyDefaults(cfg *Config) {
	if cfg.AuthPath == "" {
		cfg.AuthPath = "/oauth2/auth"
	}
	if cfg.StartPath == "" {
		cfg.StartPath = "/oauth2/start"
	}
}

// camelToSnakeUpper turns "ClientSecret" into "CLIENT_SECRET",
// "SessionEncryptionKey" into "SESSION_ENCRYPTION_KEY", etc.
// Multi-letter acronyms keep their grouping: "OIDCEndSessionURL" →
// "OIDC_END_SESSION_URL", "CACertPEM" → "CA_CERT_PEM".
func camelToSnakeUpper(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if i > 0 && isUpper(r) {
			prev := runes[i-1]
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if !isUpper(prev) || (next != 0 && !isUpper(next)) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
