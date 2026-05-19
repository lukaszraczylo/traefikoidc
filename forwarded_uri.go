package traefikoidc

import "net/http"

// originalRequestURI returns the request URI that should be used as the
// post-login redirect target. When TrustForwardedURI is enabled and the
// X-Forwarded-Uri header is present, that header wins — this lets the
// oidcgate forward-auth daemon recover the real URL when nginx/Caddy/etc
// proxied a stripped subrequest to /oauth2/auth or /oauth2/start.
func (t *TraefikOidc) originalRequestURI(req *http.Request) string {
	if t.trustForwardedURI {
		if v := req.Header.Get("X-Forwarded-Uri"); v != "" {
			return v
		}
	}
	return req.URL.RequestURI()
}
