package main

import (
	"net/http"
	"strings"
)

// mirrorAllowedHeaders is the set of NON-X-prefixed request headers that the
// success handler copies onto the response. The traefikoidc middleware sets
// "Authorization: Bearer ..." via the templated-header feature when operators
// configure it, and proxies need that to flow upstream.
var mirrorAllowedHeaders = map[string]struct{}{
	"Authorization": {},
}

// successHandler is the http.Handler installed as the middleware's `next`.
// When the middleware reaches this handler the request is authenticated; we
// mirror the X-* (and a small allow-list of non-X-*) headers the middleware
// stamped onto req.Header back onto the response so upstream proxies can
// capture them via auth_request_set / authResponseHeaders / copy_headers,
// then write 200 with an empty body.
func newSuccessHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for name, values := range req.Header {
			if !shouldMirror(name) {
				continue
			}
			for _, v := range values {
				rw.Header().Add(name, v)
			}
		}
		rw.WriteHeader(http.StatusOK)
	})
}

func shouldMirror(name string) bool {
	if strings.HasPrefix(name, "X-") {
		return true
	}
	canonical := http.CanonicalHeaderKey(name)
	_, ok := mirrorAllowedHeaders[canonical]
	return ok
}
