// Package traefikoidc — principal abstraction for the shared post-auth
// pipeline. A principal carries the resolved identity + tokens + claims
// produced by EITHER the cookie session path or the bearer-token path, so
// downstream header injection / roles checks / forwarding can be implemented
// once and reused.
package traefikoidc

// principalSource indicates which auth path produced a principal. Used by
// forwardAuthorized to decide source-specific behavior (e.g. only strip the
// Authorization header for bearer-source principals).
type principalSource int

const (
	sourceSession principalSource = iota
	sourceBearer
)

// principal is the immutable post-auth value passed to forwardAuthorized.
// No methods mutate it; no manager pointer; no I/O. Pure data.
type principal struct {
	Claims       map[string]interface{}
	Identifier   string
	Subject      string
	ClientID     string
	AccessToken  string
	IDToken      string
	RefreshToken string
	Source       principalSource
}

// buildPrincipalFromSession adapts an authenticated SessionData into a
// principal value WITHOUT writing back to the session. This is the only
// function that still knows about SessionData; the rest of the pipeline is
// session-agnostic. Returns nil when the session has no usable identity.
func (t *TraefikOidc) buildPrincipalFromSession(session *SessionData) *principal {
	if session == nil {
		return nil
	}
	identifier := session.GetUserIdentifier()
	if identifier == "" {
		return nil
	}

	var claims map[string]interface{}
	if idToken := session.GetIDToken(); idToken != "" && t.extractClaimsFunc != nil {
		// Best-effort: cached on the session, never blocking.
		claims, _ = session.GetIDTokenClaims(t.extractClaimsFunc) // Safe to ignore: claims-error path handled by header-template branch
	}

	return &principal{
		Source:       sourceSession,
		Identifier:   identifier,
		AccessToken:  session.GetAccessToken(),
		IDToken:      session.GetIDToken(),
		RefreshToken: session.GetRefreshToken(),
		Claims:       claims,
	}
}
