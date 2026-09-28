package traefikoidc

import "testing"

// TestIsLoopbackRegistrationEndpoint_HostBoundary checks the HTTP-allowed
// gate is host-bounded: http://localhost and http://127.0.0.1 pass, but
// http://localhost.evil.com (a remote host with an unfortunate name) must
// not be mistaken for loopback.
func TestIsLoopbackRegistrationEndpoint_HostBoundary(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"http://localhost/reg", true},
		{"http://127.0.0.1:8080/reg", true},
		{"http://localhost.evil.com/reg", false},
		{"http://127.0.0.1.evil.com/reg", false},
		{"http://provider.example.com/reg", false},
	}
	for _, c := range cases {
		if got := isLoopbackRegistrationEndpoint(c.in); got != c.want {
			t.Fatalf("isLoopbackRegistrationEndpoint(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
