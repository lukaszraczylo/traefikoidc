package traefikoidc

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testCertPEM returns a valid PEM-encoded certificate harvested from an
// httptest.NewTLSServer. Using httptest keeps the test free of any
// handwritten static cert that could expire.
func testCertPEM(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("httptest.NewTLSServer did not expose a certificate")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func TestLoadCACertPool_Empty(t *testing.T) {
	cfg := &Config{}
	pool, err := cfg.loadCACertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool != nil {
		t.Errorf("expected nil pool when no CA source configured, got %v", pool)
	}
}

func TestLoadCACertPool_InlinePEM(t *testing.T) {
	cfg := &Config{CACertPEM: testCertPEM(t)}
	pool, err := cfg.loadCACertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool for valid CACertPEM")
	}
}

func TestLoadCACertPool_InlinePEM_Garbage(t *testing.T) {
	cfg := &Config{CACertPEM: "not a pem"}
	pool, err := cfg.loadCACertPool()
	if err == nil {
		t.Fatal("expected error for garbage CACertPEM, got nil")
	}
	if pool != nil {
		t.Errorf("expected nil pool on error, got %v", pool)
	}
	if !strings.Contains(err.Error(), "caCertPEM") {
		t.Errorf("error should name the failing field, got: %v", err)
	}
}

func TestLoadCACertPool_FilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, []byte(testCertPEM(t)), 0o600); err != nil {
		t.Fatalf("writing temp PEM: %v", err)
	}

	cfg := &Config{CACertPath: path}
	pool, err := cfg.loadCACertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool for valid CACertPath")
	}
}

func TestLoadCACertPool_FilePath_Missing(t *testing.T) {
	cfg := &Config{CACertPath: "/does/not/exist/ca.pem"}
	pool, err := cfg.loadCACertPool()
	if err == nil {
		t.Fatal("expected error for missing CACertPath, got nil")
	}
	if pool != nil {
		t.Errorf("expected nil pool on error, got %v", pool)
	}
}

func TestLoadCACertPool_Combined(t *testing.T) {
	// Both inline and file sources populated — certificates from both should
	// be accepted into the same pool.
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, []byte(testCertPEM(t)), 0o600); err != nil {
		t.Fatalf("writing temp PEM: %v", err)
	}

	cfg := &Config{CACertPath: path, CACertPEM: testCertPEM(t)}
	pool, err := cfg.loadCACertPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool when both sources set")
	}
}

func TestSharedTransportPool_ConfigKeyDistinguishesCAAndSkipVerify(t *testing.T) {
	p := GetGlobalTransportPool()
	cfgSystem := DefaultHTTPClientConfig()

	cfgSkip := DefaultHTTPClientConfig()
	cfgSkip.InsecureSkipVerify = true

	cfgCustomCA := DefaultHTTPClientConfig()
	pool, err := (&Config{CACertPEM: testCertPEM(t)}).loadCACertPool()
	if err != nil {
		t.Fatalf("loadCACertPool: %v", err)
	}
	cfgCustomCA.RootCAs = pool

	keys := map[string]string{
		"system":   p.configKey(cfgSystem),
		"skip":     p.configKey(cfgSkip),
		"customCA": p.configKey(cfgCustomCA),
	}
	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if dup, ok := seen[key]; ok {
			t.Errorf("configKey collision: %s and %s share key %q", name, dup, key)
		}
		seen[key] = name
	}
}
