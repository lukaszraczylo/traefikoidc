package traefikoidc

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
)

// Issue #149: after NewWithContext started calling config.Validate() (commit
// 546ceb9), `headers` configs that had worked in 0.8.25 began failing, so New()
// returned a nil handler and Traefik logged the opaque router error
// "invalid handler type: <nil>". Two independent header-validation checks were
// too strict:
//
//  1. validateTemplateSecure rejected the documented multi-valued-claim join
//     pattern "{{range .. := .Claims.groups}}..." as a dangerous {{range}}.
//  2. Config.Validate required every header value to contain {{ }}, rejecting
//     static/literal values (e.g. a shared proxy secret).
//
// These tests pin the fix while proving the security boundary still holds.

// issue149BaseConfig returns a complete, valid config with no headers. Header
// cases are layered on per-test. No network is performed by Config.Validate.
func issue149BaseConfig() *Config {
	return &Config{
		ProviderURL:          "https://provider.example.com",
		ClientID:             "frigate-client",
		ClientSecret:         "frigate-client-secret",
		CallbackURL:          "/oauth2/callback",
		SessionEncryptionKey: "0123456789abcdef0123456789abcdef0123456789",
		RateLimit:            100,
		Scopes:               []string{"openid", "profile", "email", "groups"},
	}
}

// TestIssue149_HeadersConfigValidates is the exact reproduction: the issue's
// three headers (after Traefik file-provider un-escaping) must now validate.
func TestIssue149_HeadersConfigValidates(t *testing.T) {
	cfg := issue149BaseConfig()
	cfg.Headers = []TemplatedHeader{
		{Name: "X-Forwarded-Preferred-Username", Value: `{{.Claims.preferred_username}}`},
		{Name: "X-Forwarded-Groups", Value: `{{range $i, $e := .Claims.groups}}{{if $i}},{{end}}{{$e}}{{end}}`},
		{Name: "X-Proxy-Secret", Value: `super-secret-shared-value`},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("issue #149 headers config must validate after the fix, got: %v", err)
	}
}

// TestIssue149_TemplateSecurityBoundary asserts the relaxed validator accepts
// the documented range/if join over claims while still blocking genuinely
// dangerous templates and access to non-whitelisted claims.
func TestIssue149_TemplateSecurityBoundary(t *testing.T) {
	cases := []struct {
		name       string
		template   string
		shouldFail bool
	}{
		// --- allowed: documented, safe patterns ---
		{"direct claim", `{{.Claims.preferred_username}}`, false},
		{"documented groups join", `{{range $i, $e := .Claims.groups}}{{if $i}},{{end}}{{$e}}{{end}}`, false},
		{"documented roles join", `{{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}`, false},
		{"simple range over claims", `{{range .Claims.groups}}{{.}} {{end}}`, false},
		{"default over claim", `{{default "none" .Claims.email}}`, false},
		{"access token", `{{.AccessToken}}`, false},

		// --- still blocked: dangerous control/functions ---
		{"range over non-claims data", `{{range .Items}}{{.}}{{end}}`, true},
		{"call function", `{{call .Func}}`, true},
		{"define template", `{{define "x"}}{{.}}{{end}}`, true},
		{"template inclusion", `{{template "other"}}`, true},
		{"printf", `{{printf "%s" .}}`, true},

		// --- still blocked: non-whitelisted claim access, incl. via range ---
		{"non-whitelisted claim direct", `{{.Claims.password}}`, true},
		{"non-whitelisted claim via range", `{{range $i, $e := .Claims.ssn}}{{$e}}{{end}}`, true},
		{"no recognized variable", `{{.Unknown}}`, true},

		// --- still blocked: whole-Claims-map dump via range (issue #149 review, C1).
		// A decoy {{.Claims.sub}} must NOT launder a bare-map range past the gate.
		{"whole claims map dump via range", `{{range .Claims}}{{.}} {{end}}{{.Claims.sub}}`, true},
		{"claims keys dump via range assign", `{{range $k, $v := .Claims}}{{$k}} {{end}}{{.Claims.sub}}`, true},
		// --- still blocked: newline-obfuscated actions (C5) — normalize collapses
		// ALL whitespace inside delimiters, so these resolve to {{range}}/{{index}}.
		{"newline-obfuscated range over map", "{{\nrange .Claims}}{{.}}{{end}}{{.Claims.sub}}", true},
		{"newline-obfuscated index exfil", "{{\nindex .Claims \"password\"}}{{.Claims.sub}}", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTemplateSecure(tc.template)
			if tc.shouldFail && err == nil {
				t.Fatalf("expected %q to be rejected, but it passed", tc.template)
			}
			if !tc.shouldFail && err != nil {
				t.Fatalf("expected %q to be allowed, but it was rejected: %v", tc.template, err)
			}
		})
	}
}

// TestIssue149_GroupsTemplateRendersForwardableValue proves the end goal: the
// documented groups join template parses, executes to a comma-separated string,
// and passes the runtime header sanitizer — so the header is actually emitted,
// not merely accepted by validation. Parse options mirror main.go:414.
func TestIssue149_GroupsTemplateRendersForwardableValue(t *testing.T) {
	const tmplStr = `{{range $i, $e := .Claims.groups}}{{if $i}},{{end}}{{$e}}{{end}}`

	tmpl, err := template.New("X-Forwarded-Groups").Option("missingkey=zero").Parse(tmplStr)
	if err != nil {
		t.Fatalf("documented groups template must parse: %v", err)
	}

	data := map[string]any{
		"Claims": map[string]any{
			"groups": []any{"admin", "users", "viewers"},
		},
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("groups template must execute: %v", err)
	}
	if got := buf.String(); got != "admin,users,viewers" {
		t.Fatalf("groups render mismatch: got %q want %q", got, "admin,users,viewers")
	}

	// The comma-joined value must survive the runtime injection guard; commas
	// are not control/bidi runes, so it forwards intact.
	if reason := headerValueReason(buf.String(), headerTemplateMaxLen); reason != "" {
		t.Fatalf("rendered groups header was dropped by sanitizer: %s", reason)
	}
}

// TestIssue149_StaticAndDelimiterHandling covers the Config.Validate header loop
// for literal values and malformed delimiters (validateTemplateSecure is not
// invoked for pure literals).
func TestIssue149_StaticAndDelimiterHandling(t *testing.T) {
	cases := []struct {
		name        string
		value       string
		shouldFail  bool
		errContains string
	}{
		{"static literal secret", `super-secret-shared-value`, false, ""},
		{"static with equals/base64", `AAAA1234==`, false, ""},
		{"static with CRLF is rejected", "line1\r\nline2", true, "invalid characters"},
		{"unbalanced open only", `{{.Claims.email`, true, "unbalanced template delimiters"},
		{"unbalanced close only", `.Claims.email}}`, true, "unbalanced template delimiters"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := issue149BaseConfig()
			cfg.Headers = []TemplatedHeader{{Name: "X-Test", Value: tc.value}}
			err := cfg.Validate()
			if tc.shouldFail {
				if err == nil {
					t.Fatalf("expected value %q to be rejected, but it passed", tc.value)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error to contain %q, got: %v", tc.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected value %q to be allowed, but it was rejected: %v", tc.value, err)
			}
		})
	}
}
