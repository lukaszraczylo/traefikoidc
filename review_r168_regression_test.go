package traefikoidc

import "testing"

// TestR168_HeaderClaimValueRejectsQuotesAndBraces regresses the delimited-context
// header sanitizer (bearer_auth.go headerClaimRuneReason): group/role values
// and principal identifiers that get placed into a comma-joined list header
// (X-User-Groups / X-User-Roles) must also reject the bracketing characters
// " { } — not just , ; =. Old code let a value like `grp"a` or `g{r}oup`
// pass through and comma-join it verbatim, so a downstream comma-list or
// CSV/JSON-style parser consuming the header would see a corrupted /
// brace-or-quote-broken entry. Free-form templated headers (headerValueReason)
// intentionally still allow these, so this is scoped to delimited contexts.
func TestR168_HeaderClaimValueRejectsQuotesAndBraces(t *testing.T) {
	quoted := []string{`grp"a`, `grp{`, `grp}`, `adm"in`, `a{b}c`, `"}`, `x"`}
	for _, v := range quoted {
		if _, ok := sanitizeHeaderClaimValue(v, 256); ok {
			t.Errorf("delimited header value %q must be rejected (quote/brace would break a downstream list parser)", v)
		}
	}

	// The identifier path uses the same rune policy.
	ids := []string{`sub"1`, `u{r}`, `x}y`, `a"b"c`}
	for _, v := range ids {
		if _, err := sanitizeBearerIdentifier(v, 256); err == nil {
			t.Errorf("identifier %q must be rejected (quote/brace)", v)
		}
	}

	// Sanity: a realistic identifier still passes.
	if _, ok := sanitizeHeaderClaimValue("user-42@example.com", 256); !ok {
		t.Error("clean identifier must pass claim sanitization")
	}
}
