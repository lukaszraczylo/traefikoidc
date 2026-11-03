package traefikoidc

import (
	"net/http/httptest"
	"testing"
)

// Addresses in one IPv6 /64 must share one failure-tracker key.
func TestClientIPForBearerCollapsesIPv6Prefix(t *testing.T) {
	key := func(addr string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		return clientIPForBearer(r)
	}
	if a, b := key("[2001:db8:1:2::1]:1"), key("[2001:db8:1:2:ffff::9]:2"); a != b {
		t.Fatalf("same /64 got different keys: %q vs %q", a, b)
	}
	if a, b := key("[2001:db8:1:2::1]:1"), key("[2001:db8:1:3::1]:1"); a == b {
		t.Fatalf("different /64 shared key %q", a)
	}
	if got := key("192.0.2.7:80"); got != "192.0.2.7" {
		t.Fatalf("ipv4 key = %q", got)
	}
}
