package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// Issue #151: the Traefik Plugin Catalog analyzer (piceus) failed v1.0.28 with
// "failed to run the plugin with Yaegi: invalid handler type: <nil>". Two
// independent defects combined to produce that opaque report:
//
//  1. The analyzer feeds .traefik.yml testData to New() RAW — paerser and
//     mapstructure perform no brace collapsing, so the quadruple-brace header
//     values ("{{{{.Claims.email}}}}") reached Config.Validate() verbatim and
//     failed template parsing (`unexpected "{" in command`). The quadruple-brace
//     convention (commit 2d1b04c) was based on a false premise; YAML does not
//     collapse braces.
//
//  2. New() tail-called `return NewWithContext(...)`, converting the returned
//     (*TraefikOidc, error) to (http.Handler, error) in the return statement.
//     Under yaegi v0.16.1 (the interpreter piceus and Traefik embed) that
//     conversion zeroes BOTH results when the error path is taken, so piceus
//     saw (nil, nil), skipped its error branch, and reported the handler-type
//     message instead of the real validation error. Compiled Go had the sibling
//     defect: the typed-nil *TraefikOidc made New() return a NON-nil
//     http.Handler alongside a non-nil error.
//
// These tests pin both fixes natively (no interpreter needed):
// TestIssue151_ManifestTestDataPassesAnalyzer pins (1) and
// TestIssue151_NewReturnsUntypedNilHandlerOnInvalidConfig pins (2).

// manifestTestData reads .traefik.yml and returns testData exactly as the
// analyzer sees it: parsed by a YAML parser, no template preprocessing.
func manifestTestData(t *testing.T) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(".traefik.yml")
	if err != nil {
		t.Fatalf("read .traefik.yml: %v", err)
	}

	var manifest struct {
		TestData map[string]any `yaml:"testData"`
	}
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse .traefik.yml: %v", err)
	}
	if len(manifest.TestData) == 0 {
		t.Fatal(".traefik.yml has no testData — the analyzer rejects manifests without it")
	}
	return manifest.TestData
}

// TestIssue151_ManifestTestDataPassesAnalyzer decodes the manifest's testData
// into a Config the same way piceus does (defaults from CreateConfig, then the
// raw testData values on top; JSON round-trip stands in for mapstructure) and
// requires the full analyzer contract: Validate() passes and New() yields a
// working handler with no error.
func TestIssue151_ManifestTestDataPassesAnalyzer(t *testing.T) {
	testData := manifestTestData(t)

	cfg := CreateConfig()
	buf, err := json.Marshal(testData)
	if err != nil {
		t.Fatalf("marshal testData: %v", err)
	}
	if err := json.Unmarshal(buf, cfg); err != nil {
		t.Fatalf("decode testData into Config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("manifest testData must pass Validate() — the catalog analyzer feeds it to New() raw (issue #151): %v", err)
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	h, err := New(context.Background(), next, cfg, "issue151-analyzer")
	if err != nil {
		t.Fatalf("New() with manifest testData must succeed (issue #151): %v", err)
	}
	if h == nil {
		t.Fatal("New() with manifest testData returned a nil handler")
	}
	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

// TestIssue151_NewReturnsUntypedNilHandlerOnInvalidConfig requires New() to
// return an UNTYPED nil handler when construction fails. The previous
// `return NewWithContext(...)` tail call wrapped a typed-nil *TraefikOidc into
// the http.Handler interface (h != nil despite err != nil), and under yaegi the
// same statement zeroed the error as well, which is what turned every
// validation failure into Traefik's opaque "invalid handler type: <nil>".
func TestIssue151_NewReturnsUntypedNilHandlerOnInvalidConfig(t *testing.T) {
	cfg := issue149BaseConfig()
	cfg.Headers = []TemplatedHeader{
		// Invalid template — the analyzer-side shape that triggered #151.
		{Name: "X-User-Email", Value: `{{{{.Claims.email}}}}`},
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	h, err := New(context.Background(), next, cfg, "issue151-nil")
	if err == nil {
		t.Fatal("New() must reject an invalid header template")
	}
	if h != nil {
		t.Fatalf("New() must return an untyped nil handler on error, got %T (typed nil leaks through the http.Handler interface and breaks the analyzer's error reporting)", h)
	}
}
