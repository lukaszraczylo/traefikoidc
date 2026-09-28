package utils

import "testing"

// TestR176_SanitizeForwardedHostRejectsPathDelimiters regresses
// sanitizeForwardedHost: it previously only rejected control/whitespace
// characters, so a crafted X-Forwarded-Host like "example.com/path" (or
// with '?', '#', '@') survived and its delimiter was spliced verbatim into
// the host part of a redirect URL (used as redirect_uri /
// post_logout_redirect_uri and matched by the IdP). Valid host
// characters — alphanumerics, '-', '.', ':', '[', ']' (port / IPv6) —
// must still pass.
func TestR176_SanitizeForwardedHostRejectsPathDelimiters(t *testing.T) {
	valid := []string{
		"example.com",
		"example.com:8443",
		"api.v2.example.co.uk",
		"10.0.0.1",
		"[2001:db8::1]",
		"[fe80::1]:8080",
	}
	for _, in := range valid {
		if got := sanitizeForwardedHost(in); got != in {
			t.Fatalf("valid host %q was rejected: got %q", in, got)
		}
	}

	invalid := []string{
		"example.com/path", // path injection
		"example.com?x=1",  // query injection
		"example.com#frag", // fragment injection
		"user@example.com", // userinfo injection
		"example.com\\path",
		"example.com /evil", // embedded space + path
	}
	for _, in := range invalid {
		if got := sanitizeForwardedHost(in); got != "" {
			t.Fatalf("host %q must be rejected (delimiter would poison the redirect base), got %q", in, got)
		}
	}
}
