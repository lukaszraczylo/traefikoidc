package traefikoidc

import "testing"

// FuzzParseBearerJOSEHeader verifies the attacker-controlled JWT header parser
// never panics on arbitrary input (no slice OOB, no unbounded alloc, no
// JSON-engine surprise) regardless of token contents.
func FuzzParseBearerJOSEHeader(f *testing.F) {
	seeds := []string{
		"",
		"...",
		"abc.def.ghi",
		"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZDEifQ.sig.sig", // alg=RS256 kid=kid1
		"::",
		"snapshot=",
		"a,b.zzz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		parseBearerJOSEHeader(token) // must not panic
	})
}

// FuzzSanitizeBearerIdentifier verifies the identifier sanitizer never panics on
// arbitrary strings and always returns either a clean value or a *bearerError.
func FuzzSanitizeBearerIdentifier(f *testing.F) {
	seeds := []string{
		"",
		"alice",
		"user,group=admin",
		"a\u202eb\u202c",
		"\t \n",
		"verylongidentifier-padding-padding-padding-padding",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		id, berr := sanitizeBearerIdentifier(raw, 256)
		if berr == nil && id == "" {
			t.Fatalf("sanitize ok but empty identifier for %q", raw)
		}
	})
}
