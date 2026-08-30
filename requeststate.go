// Package traefikoidc provides OIDC authentication middleware for Traefik.
// requestState bundles read-mostly fields for a single ServeHTTP call.
package traefikoidc

import "net/http"

// requestState is a per-request context object allocated at the top of
// ServeHTTP and threaded through to downstream handlers. It caches values
// that would otherwise require a Yaegi-dispatched lock acquisition each time
// they're read:
//
//   - The metadata snapshot (atomic.Value.Load once, not per-handler).
//   - SessionData getter results (one RLock on sd.sessionMutex covers all
//     fields, instead of 5-7 separate RLock/RUnlock pairs scattered through
//     the handler chain).
//
// The struct is alloc'd at request entry, populated under at most one RLock
// of sd.sessionMutex, and discarded at request exit. It is NOT shared across
// requests and never written from another goroutine, so no synchronization
// on its fields is required.
//
// Cross-request global caches (tokenCache, JWKCache, sessionEntries,
// sessionInvalidationCache) remain — they're orthogonal. requestState's job
// is to eliminate redundant per-handler reads of values that don't change
// within a single request.
type requestState struct {
	// Globals snapshotted once.
	metadata *MetadataSnapshot

	// SessionData fields snapshotted under one RLock. The pointer to the
	// SessionData is retained so handlers that genuinely need to mutate
	// (Save, Clear, etc.) still have access.
	session *SessionData

	authenticated    bool
	accessToken      string
	idToken          string
	refreshToken     string
	userIdentifier   string
	createdAtUnixSec int64

	// Output: scheme/host/redirect path determined at top of ServeHTTP.
	scheme      string
	host        string
	redirectURL string

	// Carry the next handler so forwardAuthorized doesn't need to close over t.
	next http.Handler
}

// captureSession populates requestState's SessionData-derived fields under a
// single RLock of sd.sessionMutex. Returns the populated rs for chaining.
//
// Replaces a sequence of SessionData.GetX() calls each of which acquires
// sd.sessionMutex.RLock(). Under Yaegi each RLock costs ~1-5ms of
// interpreter dispatch; batching saves the rest.
func (rs *requestState) captureSession(sd *SessionData) *requestState {
	if sd == nil {
		return rs
	}
	rs.session = sd
	sd.sessionMutex.RLock()
	rs.authenticated = sd.getAuthenticatedUnsafe()
	rs.accessToken = sd.getAccessTokenUnsafe()
	rs.idToken = sd.getIDTokenUnsafe()
	rs.refreshToken = sd.getRefreshTokenUnsafe()
	rs.userIdentifier = sd.getUserIdentifierUnsafe()
	rs.createdAtUnixSec = sd.getCreatedAtUnsafe()
	sd.sessionMutex.RUnlock()
	return rs
}
