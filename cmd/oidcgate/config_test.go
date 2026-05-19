package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
