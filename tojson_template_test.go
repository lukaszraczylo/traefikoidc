package traefikoidc

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
)

// renderHeaderTemplate runs tmplStr through the same validator, funcMap and
// applyHeaderTemplates path production uses. validateErr is the static-validation
// error; got is the forwarded header value ("" when absent or dropped).
func renderHeaderTemplate(t *testing.T, tmplStr string, extraClaims []string, claims map[string]interface{}) (got string, validateErr error) {
	t.Helper()
	allowed := claimsWhitelist(extraClaims)
	if err := validateTemplateSecure(tmplStr, allowed); err != nil {
		return "", err
	}
	tmpl, err := template.New("X-Test").Funcs(headerTemplateFuncMap(allowed)).Option("missingkey=zero").Parse(tmplStr)
	if err != nil {
		t.Fatalf("validated template failed to parse: %v", err)
	}
	o := &TraefikOidc{logger: NewLogger("error"), headerTemplates: map[string]*template.Template{"X-Test": tmpl}}
	req := httptest.NewRequest("GET", "/", nil)
	o.applyHeaderTemplates(req, &principal{Claims: claims, AccessToken: "AT-SECRET", IDToken: "IDT-SECRET", RefreshToken: "RT-SECRET"})
	return req.Header.Get("X-Test"), nil
}

func TestToJson_ObjectClaimRoundTrips(t *testing.T) {
	claims := map[string]interface{}{
		"tenant": map[string]interface{}{"id": "t-1", "plan": "pro", "flags": []interface{}{"a", "b"}, "n": 3.0, "ok": true, "nil": nil},
	}
	for _, tmpl := range []string{
		`{{ get .Claims "tenant" | toJson }}`,
		`{{ toJson (get .Claims "tenant") }}`,
		`{{ toJson .Claims.tenant }}`,
		`{{ with .Claims.tenant }}{{ toJson . }}{{ end }}`,
		`{{ $t := .Claims.tenant }}{{ toJson $t }}`,
		`{{ toJson $.Claims.tenant }}`,
	} {
		got, err := renderHeaderTemplate(t, tmpl, []string{"tenant"}, claims)
		if err != nil {
			t.Fatalf("%s: unexpected validation error: %v", tmpl, err)
		}
		var back map[string]interface{}
		if err := json.Unmarshal([]byte(got), &back); err != nil {
			t.Fatalf("%s: output %q is not valid JSON: %v", tmpl, got, err)
		}
		if back["id"] != "t-1" || back["plan"] != "pro" || back["n"] != 3.0 || back["ok"] != true {
			t.Fatalf("%s: round trip mismatch: %q", tmpl, got)
		}
	}
}

func TestToJson_ValueTypes(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{"admin", "users"},
		"email":  "a@b.c",
		"exp":    1700000000.0,
		"role":   "",
	}
	cases := []struct{ name, tmpl, want string }{
		{"array", `{{ toJson .Claims.groups }}`, `["admin","users"]`},
		{"string", `{{ toJson .Claims.email }}`, `"a@b.c"`},
		{"number", `{{ toJson .Claims.exp }}`, `1700000000`},
		{"missing claim skips header", `{{ toJson .Claims.department }}`, ``},
		{"missing via get skips header", `{{ get .Claims "department" | toJson }}`, ``},
		{"empty string skips header", `{{ toJson .Claims.role }}`, ``},
		{"literal string", `{{ toJson "x" }}`, `"x"`},
		{"literal number", `{{ toJson 5 }}`, `5`},
		{"composes with surrounding text", `v={{ toJson .Claims.groups }};`, `v=["admin","users"];`},
	}
	for _, c := range cases {
		got, err := renderHeaderTemplate(t, c.tmpl, nil, claims)
		if err != nil {
			t.Fatalf("%s: unexpected validation error: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestToJson_EmptyAndNilContainers(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{},
		"groups":       []interface{}{},
	}
	if got, _ := renderHeaderTemplate(t, `{{ toJson .Claims.realm_access }}`, nil, claims); got != `{}` {
		t.Errorf("empty object: got %q", got)
	}
	if got, _ := renderHeaderTemplate(t, `{{ toJson .Claims.groups }}`, nil, claims); got != `[]` {
		t.Errorf("empty array: got %q", got)
	}
	if got, _ := renderHeaderTemplate(t, `{{ toJson .Claims.groups }}`, nil, nil); got != `` {
		t.Errorf("nil claims: got %q", got)
	}
}

func TestToJson_UnmarshalableValueDropsHeader(t *testing.T) {
	fn := headerTemplateFuncMap(nil)["toJson"].(func(interface{}) (string, error))
	if _, err := fn(make(chan int)); err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
	// A non-finite float is the only way a claim map could carry one in.
	if _, err := fn(map[string]interface{}{"x": func() {}}); err == nil {
		t.Fatal("expected error for func value")
	}
}

// Security: toJson must not widen what a template can reach.
func TestToJson_SecurityBoundary(t *testing.T) {
	claims := map[string]interface{}{
		"email":  "a@b.c",
		"secret": "NOT-WHITELISTED",
		"tenant": map[string]interface{}{"id": "t"},
	}
	rejected := []string{
		`{{ toJson . }}`,
		`{{ toJson $ }}`,
		`{{ toJson .Claims }}`,
		`{{ toJson $.Claims }}`,
		`{{ .Claims | toJson }}`,
		`{{ toJson .Claims.secret }}`,
		`{{ toJson $.Claims.secret }}`,
		`{{ toJson .AccessToken }}{{ toJson .Claims }}`,
		`{{ get .Claims "secret" | toJson }}`,
		`{{ toJson (get . "AccessToken") }}`,
		`{{ get . "Claims" | toJson }}`,
		`{{ with .Claims }}{{ toJson . }}{{ end }}`,
		`{{ range .Claims }}{{ toJson . }}{{ end }}`,
		`{{ toJson (index .Claims "secret") }}`,
		`{{ toJson (printf "%v" .Claims) }}`,
		`{{ toJson (call .Claims) }}`,
		`{{ tojson .Claims.email }}`,
		`{{ toJSON .Claims.email }}`,
		`{{ toJson | js }}`,
	}
	for _, tmpl := range rejected {
		if got, err := renderHeaderTemplate(t, tmpl, nil, claims); err == nil {
			t.Errorf("%s: must be rejected by validation, rendered %q", tmpl, got)
		}
	}

	// Dynamic key: static validation cannot see it, the runtime whitelist must.
	dyn := `{{ get .Claims .Claims.email | toJson }}`
	if got, err := renderHeaderTemplate(t, dyn, nil, map[string]interface{}{"email": "secret", "secret": "LEAK"}); err != nil || strings.Contains(got, "LEAK") {
		t.Errorf("dynamic key leaked a non-whitelisted claim: err=%v got=%q", err, got)
	}
}

// Security: tokens and the claims map never appear in output, even from a
// validated template that serializes a whitelisted claim.
func TestToJson_NoTokenLeak(t *testing.T) {
	claims := map[string]interface{}{"tenant": map[string]interface{}{"id": "t"}}
	got, err := renderHeaderTemplate(t, `{{ toJson .Claims.tenant }}`, []string{"tenant"}, claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"AT-SECRET", "IDT-SECRET", "RT-SECRET"} {
		if strings.Contains(got, s) {
			t.Fatalf("token %s leaked into %q", s, got)
		}
	}
}

// Security: a non-whitelisted claim stays unreachable until the operator opts
// in via allowedClaims, with or without toJson.
func TestToJson_RequiresAllowedClaims(t *testing.T) {
	claims := map[string]interface{}{"tenant": map[string]interface{}{"id": "t"}}
	if _, err := renderHeaderTemplate(t, `{{ toJson .Claims.tenant }}`, nil, claims); err == nil {
		t.Error("direct reference to non-whitelisted claim must be rejected")
	}
	got, err := renderHeaderTemplate(t, `{{ get .Claims "tenant" | toJson }}`, nil, claims)
	if err == nil {
		t.Errorf("literal get key outside whitelist must be rejected, rendered %q", got)
	}
}

// Security: hostile claim content must not produce header injection.
func TestToJson_HeaderInjectionHardening(t *testing.T) {
	cases := []struct {
		name  string
		value interface{}
		// forwarded reports whether the header is expected to reach upstream.
		forwarded bool
	}{
		{"CRLF is escaped to \\r\\n", map[string]interface{}{"x": "a\r\nX-Evil: 1"}, true},
		{"NUL and control chars escaped", map[string]interface{}{"x": "a\x00\x07b"}, true},
		{"LS/PS escaped", map[string]interface{}{"x": "a  b"}, true},
		{"HTML chars escaped", map[string]interface{}{"x": "<script>&"}, true},
		{"quote and backslash escaped", map[string]interface{}{"x": `"\`}, true},
		{"bidi override dropped by sanitizer", map[string]interface{}{"x": "a\u202Eb"}, false},
		{"bidi isolate dropped by sanitizer", map[string]interface{}{"x": "a\u2066b"}, false},
		{"oversize dropped by sanitizer", map[string]interface{}{"x": strings.Repeat("A", headerTemplateMaxLen)}, false},
	}
	for _, c := range cases {
		got, err := renderHeaderTemplate(t, `{{ toJson .Claims.realm_access }}`, nil, map[string]interface{}{"realm_access": c.value})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !c.forwarded {
			if got != "" {
				t.Errorf("%s: tainted value must be dropped, got %d bytes", c.name, len(got))
			}
			continue
		}
		if got == "" {
			t.Errorf("%s: safe escaped JSON must be forwarded", c.name)
			continue
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
				t.Errorf("%s: raw control rune %U in %q", c.name, r, got)
			}
		}
		if strings.ContainsAny(got, "<>&") {
			t.Errorf("%s: unescaped HTML char in %q", c.name, got)
		}
		var back map[string]interface{}
		if err := json.Unmarshal([]byte(got), &back); err != nil {
			t.Errorf("%s: not valid JSON: %v", c.name, err)
		}
	}
}

// Default-preserving: existing templates are unaffected and toJson is not
// available to anything but validated header templates.
func TestToJson_ExistingTemplatesUnchanged(t *testing.T) {
	claims := map[string]interface{}{"email": "a@b.c", "groups": []interface{}{"x", "y"}}
	got, err := renderHeaderTemplate(t, `{{ .Claims.email }}|{{range $i, $e := .Claims.groups}}{{if $i}},{{end}}{{$e}}{{end}}|{{ default "d" .Claims.role }}`, nil, claims)
	if err != nil || got != "a@b.c|x,y|d" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if _, ok := headerTemplateFuncMap(nil)["toJson"]; !ok {
		t.Fatal("toJson missing from func map")
	}
	for _, name := range []string{"env", "expandenv", "printf", "call", "index", "js"} {
		if _, ok := headerTemplateFuncMap(nil)[name]; ok {
			t.Errorf("%s must not be exposed", name)
		}
	}
}

func TestToJson_ConfigValidate(t *testing.T) {
	cfg := issue149BaseConfig()
	cfg.AllowedClaims = []string{"tenant"}
	cfg.Headers = []TemplatedHeader{{Name: "X-Tenant", Value: `{{ get .Claims "tenant" | toJson }}`}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("toJson header must validate: %v", err)
	}
	cfg.Headers = []TemplatedHeader{{Name: "X-All", Value: `{{ toJson .Claims }}`}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("toJson of whole Claims must fail validation")
	}
}

// Oversize output is operator-actionable, so it logs at error level (name and
// size limit only, never the value); other sanitizer drops stay at debug.
func TestToJson_OversizeLogsError(t *testing.T) {
	run := func(claim map[string]interface{}) string {
		var buf strings.Builder
		logger := NewLogger("debug")
		logger.logError.SetOutput(&buf)
		tmpl := template.Must(template.New("X-Test").Funcs(headerTemplateFuncMap(nil)).Parse(`{{ toJson .Claims.realm_access }}`))
		o := &TraefikOidc{logger: logger, headerTemplates: map[string]*template.Template{"X-Test": tmpl}}
		req := httptest.NewRequest("GET", "/", nil)
		o.applyHeaderTemplates(req, &principal{Claims: map[string]interface{}{"realm_access": claim}})
		if req.Header.Get("X-Test") != "" {
			t.Fatal("tainted header must be dropped")
		}
		return buf.String()
	}
	big := strings.Repeat("S3CRET", headerTemplateMaxLen)
	out := run(map[string]interface{}{"x": big})
	if !strings.Contains(out, "X-Test") || !strings.Contains(out, "exceeds") {
		t.Errorf("oversize must log an error naming the header, got %q", out)
	}
	if strings.Contains(out, "S3CRET") {
		t.Error("error log must not contain the value")
	}
	if out := run(map[string]interface{}{"x": "a\u202Eb"}); out != "" {
		t.Errorf("non-length sanitizer drop must not log at error level, got %q", out)
	}
}
