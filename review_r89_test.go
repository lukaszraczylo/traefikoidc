package traefikoidc

import (
	"net/http"
	"testing"
)

// R89 regression: pathExcluded matched the RAW request path as a string
// prefix. Go's server leaves ".." in req.URL.Path (url.ParseRequestURI does
// not normalize dot segments), so an exclusion for "/public" also matched
// "/public/../admin", letting a dot-segment traversal reach a sibling
// resource (e.g. /admin) unauthenticated. The matcher must normalize the
// request path (path.Clean) before the boundary comparison so traversal
// cannot widen an exclusion into an authentication bypass.
func TestR89ExcludedPathDotTraversal(t *testing.T) {
	// Exact-matching and legitimate-subtree exclusions must be preserved.
	if !pathExcluded("/public", "/public") {
		t.Error("exact match should be excluded")
	}
	if !pathExcluded("/public/page", "/public") {
		t.Error("sub-path should still be excluded")
	}
	if !pathExcluded("/public/./page", "/public") {
		t.Error("un-escaped ./ inside the excluded subtree should still be excluded")
	}

	// Dot-segment traversal must NOT escape INTO the exclusion namespace and
	// thereby reach a sibling resource unauthenticated.
	if pathExcluded("/public/../admin", "/public") {
		t.Error("excluded /public must not also cover /admin reached via ../ (auth bypass)")
	}
	if pathExcluded("/public/..", "/public") {
		t.Error("excluded /public must not cover root reached via ..")
	}
	if pathExcluded("/public/../", "/public") {
		t.Error("excluded /public must not cover the bare root reached via ../")
	}
	if pathExcluded("/public/x/../../admin", "/public") {
		t.Error("nested traversal must not escape the subtree into /admin")
	}
}

// R89 regression: CreatePooledHTTPClient / GetOrCreateTransport must apply the
// same zero-value defaults as CreateHTTPClient. Before, a partially populated
// config (e.g. only {Timeout: 10s}, or zero) produced an http.Client with
// Timeout == 0 and a transport with ResponseHeaderTimeout == 0 — an unbounded
// stall on a hanging upstream. Both must now be bounded by the shared
// defaults.
func TestR89PooledClientAppliesDefaults(t *testing.T) {
	client := CreatePooledHTTPClient(HTTPClientConfig{})
	if client.Timeout == 0 {
		t.Error("pooled HTTP client must carry a default overall Timeout; zero = unbounded stall")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("pooled client transport is %T, want *http.Transport", client.Transport)
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("pooled transport must carry a default ResponseHeaderTimeout; zero = unbounded stall")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("pooled transport must carry a default IdleConnTimeout")
	}
}
