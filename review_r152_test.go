package traefikoidc

import (
	"testing"
)

// TestIsAllowedDomain_SubdomainGranted guards the R152 fix to
// utilities.go isAllowedDomain: allowedUserDomains matched only the exact
// whole domain, so a user on a corporate subdomain
// (user@marketing.company.com) was silently denied even though the
// operator's "company.com" intended to cover the org. A configured
// domain now also grants its subdomains.
func TestIsAllowedDomain_SubdomainGranted(t *testing.T) {
	tObj := &TraefikOidc{
		logger:             GetSingletonNoOpLogger(),
		allowedUserDomains: map[string]struct{}{"company.com": {}},
	}
	if !tObj.isAllowedDomain("user@mail.company.com") {
		t.Fatal("a subdomain of an allowed domain must be granted")
	}
	if !tObj.isAllowedDomain("user@a.b.company.com") {
		t.Fatal("a deep subdomain of an allowed domain must be granted")
	}
	// Exact match still works and unrelated domains still denied.
	if !tObj.isAllowedDomain("user@company.com") {
		t.Fatal("exact allowed domain must still be granted")
	}
	if tObj.isAllowedDomain("user@othercompany.com") {
		t.Fatal("a different domain sharing the suffix must NOT be granted")
	}
	if tObj.isAllowedDomain("user@badexample.com") {
		t.Fatal("a domain merely ending in the allowed one must NOT be granted")
	}
}
