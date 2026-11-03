package traefikoidc

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

// An IPv6 /64 holder must share one bucket; per-address keys let one host
// mint 2^64 buckets and bypass the throttle.
func TestPerSourceLimiter_IPv6SamePrefixSharesBucket(t *testing.T) {
	const burst = 3
	l := newPerSourceAuthLimiter(burst)
	allowed := 0
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:1234", i+1)
		if l.allow(req) {
			allowed++
		}
	}
	if allowed > burst {
		t.Fatalf("one /64 got %d allows, want <= %d", allowed, burst)
	}
}

func TestPerSourceLimiter_IPv6DifferentPrefixIndependent(t *testing.T) {
	l := newPerSourceAuthLimiter(1)
	a := httptest.NewRequest("GET", "/", nil)
	a.RemoteAddr = "[2001:db8:1:2::1]:1"
	b := httptest.NewRequest("GET", "/", nil)
	b.RemoteAddr = "[2001:db8:1:3::1]:1"
	if !l.allow(a) || !l.allow(b) {
		t.Fatal("distinct /64 prefixes must have independent buckets")
	}
}

func TestLimiterKey(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":        "192.0.2.1",
		"2001:db8:1:2::9":  "2001:db8:1:2::/64",
		"::ffff:192.0.2.1": "192.0.2.1",
	}
	for in, want := range cases {
		if got := limiterKey(in); got != want {
			t.Errorf("limiterKey(%q)=%q want %q", in, got, want)
		}
	}
}
