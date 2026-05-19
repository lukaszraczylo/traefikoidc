package main

import "net/http"

// sentinelPath is the synthetic request path used when delegating /oauth2/auth
// and /oauth2/start into the traefikoidc middleware. It must NOT collide with
// callbackURL, logoutURL, /health*, or any plausible excludedURLs entry —
// the underscores and double-prefixing make accidental matches near-impossible.
const sentinelPath = "/__oidcgate_protected__"

// newAuthHandler builds the /oauth2/auth (silent probe) handler.
// Rewrites the request path to sentinelPath, wraps the ResponseWriter to
// convert the middleware's 302→IdP into 401, and delegates.
func newAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ic := newAuthInterceptor(rw)
		defer ic.Finalize()
		r2 := cloneAndRewrite(req, sentinelPath)
		next.ServeHTTP(ic, r2)
	})
}

// newStartHandler builds the /oauth2/start (visible sign-in) handler.
// Rewrites the path to sentinelPath, forwards any ?rd= query as
// X-Forwarded-Uri so the middleware (with TrustForwardedURI=true) captures
// the right post-login redirect target, then delegates. The middleware's
// natural 302→IdP flows through unchanged.
func newStartHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		r2 := cloneAndRewrite(req, sentinelPath)
		if rd := req.URL.Query().Get("rd"); rd != "" && r2.Header.Get("X-Forwarded-Uri") == "" {
			r2.Header.Set("X-Forwarded-Uri", rd)
		}
		next.ServeHTTP(rw, r2)
	})
}

// newCallbackHandler builds the IdP callback endpoint.
// Rewrites the request path to the configured callbackURL so the middleware's
// path-match at the top of ServeHTTP triggers the callback flow.
func newCallbackHandler(next http.Handler, callbackURL string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		r2 := cloneAndRewrite(req, callbackURL)
		next.ServeHTTP(rw, r2)
	})
}

// newLogoutHandler builds the logout endpoint.
// Rewrites the request path to the configured logoutURL so the middleware's
// path-match at the top of ServeHTTP triggers the logout flow.
func newLogoutHandler(next http.Handler, logoutURL string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		r2 := cloneAndRewrite(req, logoutURL)
		next.ServeHTTP(rw, r2)
	})
}

// cloneAndRewrite returns a shallow clone of req with URL.Path set to newPath.
// The query string is preserved verbatim — middleware logic for code/state
// extraction reads URL.Query() which still works.
func cloneAndRewrite(req *http.Request, newPath string) *http.Request {
	r2 := req.Clone(req.Context())
	u := *req.URL
	u.Path = newPath
	r2.URL = &u
	return r2
}
