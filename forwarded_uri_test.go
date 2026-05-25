package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginalRequestURI_DefaultOff(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: false}
	req := httptest.NewRequest(http.MethodGet, "/protected?x=1", nil)
	req.Header.Set("X-Forwarded-Uri", "/spoofed")
	if got := tr.originalRequestURI(req); got != "/protected?x=1" {
		t.Fatalf("default-off: want /protected?x=1, got %q", got)
	}
}

func TestOriginalRequestURI_TrustEnabled(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: true}
	req := httptest.NewRequest(http.MethodGet, "/protected?x=1", nil)
	req.Header.Set("X-Forwarded-Uri", "/real?y=2")
	if got := tr.originalRequestURI(req); got != "/real?y=2" {
		t.Fatalf("trust-on with header: want /real?y=2, got %q", got)
	}
}

func TestOriginalRequestURI_TrustEnabledNoHeader(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: true}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if got := tr.originalRequestURI(req); got != "/protected" {
		t.Fatalf("trust-on no header: want /protected, got %q", got)
	}
}
func TestOriginalRequestURI_RejectsAbsoluteURL(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: true}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Forwarded-Uri", "https://evil.example/phish")
	if got := tr.originalRequestURI(req); got != "/protected" {
		t.Fatalf("absolute URL must be rejected, want /protected fallback, got %q", got)
	}
}

func TestOriginalRequestURI_RejectsProtocolRelative(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: true}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Forwarded-Uri", "//evil.example/phish")
	if got := tr.originalRequestURI(req); got != "/protected" {
		t.Fatalf("protocol-relative URL must be rejected, want /protected fallback, got %q", got)
	}
}

func TestOriginalRequestURI_AcceptsSafePathWithQuery(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: true}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Forwarded-Uri", "/safe?x=1&y=2")
	if got := tr.originalRequestURI(req); got != "/safe?x=1&y=2" {
		t.Fatalf("safe path with query must be accepted, got %q", got)
	}
}

func TestOriginalRequestURI_RejectsBareHostnameNoSlash(t *testing.T) {
	tr := &TraefikOidc{trustForwardedURI: true}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Forwarded-Uri", "evil.example/phish")
	if got := tr.originalRequestURI(req); got != "/protected" {
		t.Fatalf("non-/ prefix must be rejected, got %q", got)
	}
}

