package utils

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestDetermineScheme verifies the scheme priority: forceHTTPS > X-Forwarded-Proto > TLS > http.
func TestDetermineScheme(t *testing.T) {
	cases := []struct {
		name        string
		forceHTTPS  bool
		fwdProto    string
		tls         bool
		want        string
	}{
		{"force https wins over header", true, "http", false, "https"},
		{"force https wins over tls absence", true, "", false, "https"},
		{"forwarded proto used", false, "https", false, "https"},
		{"forwarded proto http", false, "http", true, "http"},
		{"tls connection", false, "", true, "https"},
		{"default http", false, "", false, "http"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &http.Request{}
			if c.fwdProto != "" {
				req.Header = http.Header{"X-Forwarded-Proto": {c.fwdProto}}
			}
			if c.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if got := DetermineScheme(req, c.forceHTTPS); got != c.want {
				t.Fatalf("DetermineScheme() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestDetermineHost verifies forwarding-header preference and fallback to req.Host.
func TestDetermineHost(t *testing.T) {
	cases := []struct {
		name  string
		fwd   string
		host  string
		want  string
	}{
		{"forwarded host used", "api.example.com", "backend.local", "api.example.com"},
		{"first of comma list taken", "a.example.com, b.example.com", "backend.local", "a.example.com"},
		{"empty forwarded falls back to host", "", "backend.local", "backend.local"},
		{"whitespace forwarded falls back", "   ", "backend.local", "backend.local"},
		{"control-char forwarded rejected", "ok.example.com\r\nInjected: yes", "backend.local", "backend.local"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &http.Request{Host: c.host}
			if c.fwd != "" {
				req.Header = http.Header{"X-Forwarded-Host": {c.fwd}}
			}
			if got := DetermineHost(req); got != c.want {
				t.Fatalf("DetermineHost() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSanitizeForwardedHost verifies CRLF/newline rejection so crafted headers cannot
// poison redirect URLs built from the result.
func TestSanitizeForwardedHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty rejected", "", ""},
		{"plain accepted", "api.example.com", "api.example.com"},
		{"first of comma list", "a.example.com,b.example.com", "a.example.com"},
		{"leading/trailing space trimmed", "  api.example.com  ", "api.example.com"},
		{"internal space rejected", "api example.com", ""},
		{"CRLF rejected", "api.example.com\r\nX-Injected: 1", ""},
		{"bare LF rejected", "api.example.com\ngo", ""},
		{"tab rejected", "api.example.com\x09evil", ""},
		{"DEL rejected", "api.example.com\x7f", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeForwardedHost(c.in); got != c.want {
				t.Fatalf("sanitizeForwardedHost(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
