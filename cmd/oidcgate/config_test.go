package main

import (
	"os"
	"path/filepath"
	"testing"
)

// minimalYAML is a base config accepted by Load with no surprises.
const minimalYAML = `
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_YAMLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
listen: ":9090"
authPath: "/auth"
startPath: "/start"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("listen: want :9090, got %q", cfg.Listen)
	}
	if cfg.AuthPath != "/auth" {
		t.Errorf("authPath: want /auth, got %q", cfg.AuthPath)
	}
	if cfg.StartPath != "/start" {
		t.Errorf("startPath: want /start, got %q", cfg.StartPath)
	}
	if cfg.OIDC.ClientID != "abc" {
		t.Errorf("clientID: want abc, got %q", cfg.OIDC.ClientID)
	}
	if cfg.OIDC.ClientSecret != "secret" {
		t.Errorf("clientSecret: want secret, got %q", cfg.OIDC.ClientSecret)
	}
	if !cfg.OIDC.TrustForwardedURI {
		t.Errorf("TrustForwardedURI should be forced true by Load")
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "from-file"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIDCGATE_CLIENT_SECRET", "from-env")
	t.Setenv("OIDCGATE_LISTEN", ":9999")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.ClientSecret != "from-env" {
		t.Errorf("env override (clientSecret): want from-env, got %q", cfg.OIDC.ClientSecret)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("env override (listen): want :9999, got %q", cfg.Listen)
	}
}

func TestLoad_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthPath != "/oauth2/auth" {
		t.Errorf("AuthPath default: want /oauth2/auth, got %q", cfg.AuthPath)
	}
	if cfg.StartPath != "/oauth2/start" {
		t.Errorf("StartPath default: want /oauth2/start, got %q", cfg.StartPath)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/config.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_NestedStructRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
redis:
  address: "redis:6379"
  password: "redispw"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Redis == nil {
		t.Fatal("redis block should populate cfg.OIDC.Redis")
	}
	if cfg.OIDC.Redis.Address != "redis:6379" {
		t.Errorf("redis address: want redis:6379, got %q", cfg.OIDC.Redis.Address)
	}
}

// Fix 5: callbackURL / logoutURL must start with "/"
func TestLoad_RejectsAbsoluteCallbackURL(t *testing.T) {
	path := writeConfig(t, `
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "https://app.example.com/oauth2/callback"
logoutURL: "/oauth2/logout"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("callbackURL with absolute URL must be rejected")
	}
}

func TestLoad_RejectsAbsoluteLogoutURL(t *testing.T) {
	path := writeConfig(t, `
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "https://app.example.com/oauth2/logout"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("logoutURL with absolute URL must be rejected")
	}
}

// Fix 2: excludedURLs must not prefix reserved paths
func TestLoad_RejectsExcludedURLPrefixingReservedPath(t *testing.T) {
	path := writeConfig(t, `
listen: ":8080"
providerURL: "https://idp.example"
clientID: "abc"
clientSecret: "secret"
sessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
callbackURL: "/oauth2/callback"
logoutURL: "/oauth2/logout"
excludedURLs: ["/"]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("excludedURLs: ['/'] must be rejected (bypasses all reserved paths)")
	}
}

func TestLoad_AllowsNonOverlappingExcludedURL(t *testing.T) {
	path := writeConfig(t, minimalYAML+`excludedURLs: ["/public"]
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("non-overlapping excludedURL must be accepted: %v", err)
	}
}

// Fix 3: env override coverage — every envScalarFields entry must have a
// matching case in setScalarField. isAllZeroForField detects drift.
func TestEnvOverrideCoverage(t *testing.T) {
	for _, field := range envScalarFields {
		field := field
		t.Run(field, func(t *testing.T) {
			probe := "/safe/probe-" + field
			if field == "SessionEncryptionKey" {
				probe = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
			}
			if field == "LogLevel" {
				probe = "debug"
			}
			if field == "ClientAuthMethod" {
				probe = "client_secret_post"
			}
			if field == "ClientAssertionAlg" {
				probe = "RS256"
			}

			var fresh Config
			setScalarField(&fresh, field, probe)
			if isAllZeroForField(&fresh, field, probe) {
				t.Fatalf("envScalarFields includes %q but setScalarField has no matching case (drift)", field)
			}
		})
	}
}

// isAllZeroForField returns true when setScalarField did NOT set the expected
// field — i.e., the switch is missing a case for `field`.
func isAllZeroForField(cfg *Config, field, probe string) bool {
	switch field {
	case "Listen":
		return cfg.Listen != probe
	case "AuthPath":
		return cfg.AuthPath != probe
	case "StartPath":
		return cfg.StartPath != probe
	case "ProviderURL":
		return cfg.OIDC.ProviderURL != probe
	case "ClientID":
		return cfg.OIDC.ClientID != probe
	case "ClientSecret":
		return cfg.OIDC.ClientSecret != probe
	case "Audience":
		return cfg.OIDC.Audience != probe
	case "CallbackURL":
		return cfg.OIDC.CallbackURL != probe
	case "LogoutURL":
		return cfg.OIDC.LogoutURL != probe
	case "PostLogoutRedirectURI":
		return cfg.OIDC.PostLogoutRedirectURI != probe
	case "SessionEncryptionKey":
		return cfg.OIDC.SessionEncryptionKey != probe
	case "CookiePrefix":
		return cfg.OIDC.CookiePrefix != probe
	case "CookieDomain":
		return cfg.OIDC.CookieDomain != probe
	case "LogLevel":
		return cfg.OIDC.LogLevel != probe
	case "RevocationURL":
		return cfg.OIDC.RevocationURL != probe
	case "OIDCEndSessionURL":
		return cfg.OIDC.OIDCEndSessionURL != probe
	case "UserIdentifierClaim":
		return cfg.OIDC.UserIdentifierClaim != probe
	case "GroupClaimName":
		return cfg.OIDC.GroupClaimName != probe
	case "RoleClaimName":
		return cfg.OIDC.RoleClaimName != probe
	case "ClientAuthMethod":
		return cfg.OIDC.ClientAuthMethod != probe
	case "ClientAssertionPrivateKey":
		return cfg.OIDC.ClientAssertionPrivateKey != probe
	case "ClientAssertionKeyPath":
		return cfg.OIDC.ClientAssertionKeyPath != probe
	case "ClientAssertionKeyID":
		return cfg.OIDC.ClientAssertionKeyID != probe
	case "ClientAssertionAlg":
		return cfg.OIDC.ClientAssertionAlg != probe
	case "CACertPath":
		return cfg.OIDC.CACertPath != probe
	case "CACertPEM":
		return cfg.OIDC.CACertPEM != probe
	}
	return true // unknown field → drift
}
