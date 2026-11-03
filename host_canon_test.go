package traefikoidc

import "testing"

func TestValidateHostCanonicalForms(t *testing.T) {
	o := &TraefikOidc{}
	blocked := []string{
		"localhost.", "LOCALHOST.", "metadata.google.internal.", "metadata.google.internal",
		"169.254.169.254.", "fe80::1%eth0", "[fe80::1]", "::1",
	}
	for _, h := range blocked {
		if err := o.validateHost(h); err == nil {
			t.Errorf("validateHost(%q) = nil, want blocked", h)
		}
	}
	allowed := []string{"idp.example.com", "idp.example.com.", "2606:4700::1111"}
	for _, h := range allowed {
		if err := o.validateHost(h); err != nil {
			t.Errorf("validateHost(%q) = %v, want allowed", h, err)
		}
	}
	if !isLoopbackHost("localhost.") {
		t.Error("isLoopbackHost(localhost.) = false")
	}
}
