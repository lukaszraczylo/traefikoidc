package traefikoidc

// Ready reports whether the middleware has completed at least one successful
// OIDC provider metadata discovery. Used by external supervisors (e.g. the
// oidcgate /readyz endpoint) to gate traffic until the IdP discovery doc
// has been fetched and the authorization endpoint is known.
func (t *TraefikOidc) Ready() bool {
	t.metadataMu.RLock()
	defer t.metadataMu.RUnlock()
	return t.authURL != ""
}
