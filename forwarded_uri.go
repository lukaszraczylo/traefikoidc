package traefikoidc

import (
	"net/http"
	"net/url"
	"strings"
)

// originalRequestURI returns the request URI that should be used as the
// post-login redirect target. When TrustForwardedURI is enabled and the
// X-Forwarded-Uri header carries a safe same-origin path, that header
// wins. Otherwise (or if the header is missing/unsafe), falls back to
// req.URL.RequestURI() — the path the request reached the proxy with.
//
// "Safe" means: starts with "/", does NOT start with "//" (protocol-relative
// URLs can change host), and has no scheme or host after parsing. This
// prevents an attacker-controllable header from triggering an open redirect
// via http.Redirect later in the auth flow.
func (t *TraefikOidc) originalRequestURI(req *http.Request) string {
	if t.trustForwardedURI {
		if v := req.Header.Get("X-Forwarded-Uri"); v != "" && isSafeRedirectTarget(v) {
			return v
		}
	}
	return req.URL.RequestURI()
}

func isSafeRedirectTarget(v string) bool {
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return false
	}
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	return u.Host == "" && u.Scheme == ""
}
