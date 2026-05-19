package main

import "net/http"

// authInterceptor wraps a ResponseWriter for the /oauth2/auth endpoint.
// The traefikoidc middleware emits an HTTP 302 to the IdP authorize URL
// when a request is unauthenticated, but nginx auth_request and similar
// silent-probe contracts cannot follow redirects. authInterceptor buffers
// the header/body and, at Finalize() time:
//
//   - if status was a redirect class (302, 303, 307, 308), rewrites it
//     to 401, moves the original Location header to X-Auth-Redirect
//     (advisory), strips Location, preserves Set-Cookie headers (state,
//     PKCE, nonce — the browser will carry them into the next request),
//     and writes an empty body.
//   - otherwise: passes through verbatim.
type authInterceptor struct {
	inner       http.ResponseWriter
	headers     http.Header
	status      int
	body        []byte
	wroteHeader bool
	finalized   bool
}

func newAuthInterceptor(inner http.ResponseWriter) *authInterceptor {
	return &authInterceptor{
		inner:   inner,
		headers: http.Header{},
		status:  http.StatusOK,
	}
}

func (w *authInterceptor) Header() http.Header { return w.headers }

func (w *authInterceptor) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
}

func (w *authInterceptor) Write(b []byte) (int, error) { //nolint:unparam // signature mandated by http.ResponseWriter
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	w.body = append(w.body, b...)
	return len(b), nil
}

// Finalize flushes the buffered response, applying the 302/303 → 401 rewrite.
// Must be called exactly once after the wrapped handler returns.
func (w *authInterceptor) Finalize() {
	if w.finalized {
		return
	}
	w.finalized = true
	switch w.status {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		// Move Location → X-Auth-Redirect, strip Location, force 401, drop body.
		if loc := w.headers.Get("Location"); loc != "" {
			w.headers.Set("X-Auth-Redirect", loc)
			w.headers.Del("Location")
		}
		copyHeaders(w.inner.Header(), w.headers)
		w.inner.WriteHeader(http.StatusUnauthorized)
		return
	}
	copyHeaders(w.inner.Header(), w.headers)
	w.inner.WriteHeader(w.status)
	if len(w.body) > 0 {
		_, _ = w.inner.Write(w.body)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
