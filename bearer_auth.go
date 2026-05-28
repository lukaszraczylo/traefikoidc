// Package traefikoidc — bearer-token (M2M) authentication path.
//
// Disabled by default. When enabled via Config.EnableBearerAuth, requests
// presenting "Authorization: Bearer <jwt>" are validated against the
// configured OIDC provider (signature, issuer, audience, exp, replay-Get)
// and the request is forwarded downstream without creating a cookie session.
//
// Design rules (kept here in code as the single source of truth):
//   - Access tokens only. ID tokens are rejected via detectTokenType.
//   - Audience is mandatory (enforced at startup in main.go).
//   - alg + kid pinned BEFORE JWKS fetch to deny amplification probes.
//   - iat upper-age cap bounds clock-skew / forever-token abuse.
//   - Multi-audience tokens require matching azp.
//   - Per-IP 401 throttle returns 429 + Retry-After after a threshold.
//   - JTI Set is suppressed (skipReplayMarking) but JTI Get stays — revoked
//     tokens (RevokeToken adds to blacklist) are still rejected.
//   - Identifier is read from BearerIdentifierClaim (default "sub"), never
//     from UserIdentifierClaim, to avoid the unverified-email spoofing path.
//   - Identifier is sanitized: length cap, control chars, bidi-override,
//     delimiter chars (, ; =) rejected.
//   - On excluded URLs the Authorization header is stripped before forwarding.
//
// See docs/superpowers/specs/2026-05-18-bearer-token-auth-design.md and
// docs/BEARER_AUTH.md for the full threat model.
package traefikoidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
)

const bearerPrefix = "Bearer "

// bearerAlgAllowlist is the set of JWS algorithms accepted on the bearer
// path. Asymmetric-only — HS* would allow public-key-as-HMAC-secret attacks
// if any operator ever rotates a key into the symmetric branch by mistake;
// "none" is obvious. Matches the allowlist enforced inside jwt.Verify but is
// checked here BEFORE the JWKS fetch so attacker noise can't amplify.
var bearerAlgAllowlist = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
}

// bearerKidMaxLen caps the JOSE kid header length to keep memory and cache-key
// usage bounded against attacker-controlled values.
const bearerKidMaxLen = 256

// validKidChar is the allowlist for kid header characters. Letters, digits,
// dot, underscore, hyphen, equals. Intentionally narrow; real-world kid
// values are short URL-safe-base64-ish identifiers.
func validKidChar(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '.', '_', '-', '=':
		return true
	}
	return false
}

// bearerError categorizes failure modes for the response builder. Categories
// map 1:1 to the table in docs/superpowers/specs/2026-05-18-bearer-token-auth-design.md
// §9 so behavior is auditable from spec to code.
type bearerErrorKind int

const (
	bearerErrInvalidRequest bearerErrorKind = iota
	bearerErrInvalidToken
	bearerErrTokenInactive
	bearerErrInvalidIdentifier
	bearerErrForbidden
	bearerErrThrottled
	bearerErrIntrospectionUnavailable
)

type bearerError struct {
	kind   bearerErrorKind
	reason string
}

func (e *bearerError) Error() string { return e.reason }

func newBearerError(kind bearerErrorKind, reason string) *bearerError {
	return &bearerError{kind: kind, reason: reason}
}

// joseHeader is the minimal subset of the JWS protected header we inspect
// BEFORE running the full verification pipeline. Lifted out so the alg+kid
// pin can run without paying for parseJWT's full claim decode.
type joseHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// parseBearerJOSEHeader decodes the first JWT segment for early alg/kid pinning.
// Does not touch the payload or signature — those are the verifier's job.
// Returns nil on success; *bearerError on rejection so the handler can map
// directly to a status code. The decoded header itself is not surfaced because
// callers don't need it (verifyTokenWithOpts re-parses internally).
func parseBearerJOSEHeader(token string) *bearerError {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return newBearerError(bearerErrInvalidToken, "malformed JWT: no header segment")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		// Some IdPs pad with '='; tolerate by retrying with StdEncoding.
		raw, err = base64.URLEncoding.DecodeString(token[:dot])
		if err != nil {
			return newBearerError(bearerErrInvalidToken, "malformed JWT: header not base64url")
		}
	}
	var hdr joseHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return newBearerError(bearerErrInvalidToken, "malformed JWT: header not JSON")
	}
	if _, ok := bearerAlgAllowlist[hdr.Alg]; !ok {
		return newBearerError(bearerErrInvalidToken, fmt.Sprintf("disallowed alg %q on bearer path", hdr.Alg))
	}
	if hdr.Kid == "" {
		return newBearerError(bearerErrInvalidToken, "missing kid header")
	}
	if len(hdr.Kid) > bearerKidMaxLen {
		return newBearerError(bearerErrInvalidToken, "kid header exceeds max length")
	}
	for _, r := range hdr.Kid {
		if !validKidChar(r) {
			return newBearerError(bearerErrInvalidToken, "kid header contains disallowed characters")
		}
	}
	return nil
}

// sanitizeBearerIdentifier validates and trims a principal identifier before
// it is injected into request headers. Layered defense: net/http will reject
// CRLF on the wire too, but rejecting early gives clearer error logs and
// prevents bidi-override / delimiter chars that pass net/http's narrower
// checks but confuse downstream parsers and admin UIs.
func sanitizeBearerIdentifier(raw string, maxLen int) (string, *bearerError) {
	identifier := strings.TrimSpace(raw)
	if identifier == "" {
		return "", newBearerError(bearerErrInvalidIdentifier, "identifier claim empty")
	}
	if maxLen > 0 && len(identifier) > maxLen {
		return "", newBearerError(bearerErrInvalidIdentifier, "identifier exceeds max length")
	}
	for _, r := range identifier {
		if unicode.IsControl(r) {
			return "", newBearerError(bearerErrInvalidIdentifier, "identifier contains control character")
		}
		// Unicode bidi-override range (RTL spoofing of admin UI / SIEM).
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return "", newBearerError(bearerErrInvalidIdentifier, "identifier contains bidi-override character")
		}
		if r == ',' || r == ';' || r == '=' {
			return "", newBearerError(bearerErrInvalidIdentifier, "identifier contains delimiter character")
		}
	}
	return identifier, nil
}

// resolveBearerIdentifier picks the principal identifier from claims using
// the configured BearerIdentifierClaim (default "sub"). Decoupled from
// userIdentifierClaim (cookie path) to avoid the unverified-email spoofing
// vector documented in the spec §13.
func resolveBearerIdentifier(claims map[string]interface{}, claimName string) (string, *bearerError) {
	if claimName == "" {
		claimName = "sub"
	}
	raw, ok := claims[claimName]
	if !ok {
		return "", newBearerError(bearerErrInvalidIdentifier, fmt.Sprintf("missing claim %q", claimName))
	}
	str, ok := raw.(string)
	if !ok {
		return "", newBearerError(bearerErrInvalidIdentifier, fmt.Sprintf("claim %q not a string", claimName))
	}
	return str, nil
}

// enforceMultiAudienceAzp implements the spec hardening: when aud is a
// multi-element array, require an azp claim equal to clientID. Single-string
// aud is unaffected (existing verifyAudience handles it).
func enforceMultiAudienceAzp(claims map[string]interface{}, clientID string) *bearerError {
	audRaw, ok := claims["aud"]
	if !ok {
		return nil // verifyToken already rejects missing aud
	}
	arr, ok := audRaw.([]interface{})
	if !ok {
		return nil // single-string aud
	}
	if len(arr) <= 1 {
		return nil
	}
	azpRaw, ok := claims["azp"]
	if !ok {
		return newBearerError(bearerErrInvalidToken, "multi-audience token missing azp")
	}
	azp, ok := azpRaw.(string)
	if !ok || azp == "" {
		return newBearerError(bearerErrInvalidToken, "multi-audience token has empty/non-string azp")
	}
	if azp != clientID {
		return newBearerError(bearerErrInvalidToken, "multi-audience token azp does not match clientID")
	}
	return nil
}

// enforceIatAge implements the spec MaxTokenAgeSeconds bound on iat. Bounds
// clock-manipulation / forever-token abuse without rejecting tokens with a
// normal iat just because the issuer's clock skews a few seconds.
func enforceIatAge(claims map[string]interface{}, maxAge time.Duration) *bearerError {
	if maxAge <= 0 {
		return nil
	}
	iatRaw, ok := claims["iat"].(float64)
	if !ok {
		// jwt.Verify already requires iat; this branch shouldn't be reached.
		return newBearerError(bearerErrInvalidToken, "missing iat claim")
	}
	iat := time.Unix(int64(iatRaw), 0)
	if time.Since(iat) > maxAge {
		return newBearerError(bearerErrInvalidToken, "token iat outside age bound")
	}
	return nil
}

// hashIdentifierForLog returns a short SHA-256 prefix safe for info-level
// logs. Full identifier is only emitted at debug. Satisfies the audit
// requirement (trace which principal was rejected) without leaking PII.
func hashIdentifierForLog(identifier string) string {
	if identifier == "" {
		return "(none)"
	}
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:4]) // 8 hex chars
}

// --- Per-IP failure throttle ---

// bearerFailureTracker records consecutive bearer-auth 401s per source IP and
// parks repeat offenders in a 429 penalty box. Limits offline-guessing-style
// attacks and protects the shared rate-limiter / JWKS endpoint from being
// burned by a single source.
type bearerFailureTracker struct {
	mu      sync.Mutex
	entries map[string]*bearerFailureEntry
	// Configuration snapshot. Captured at construction so a hot reconfigure
	// doesn't race with the per-request paths.
	threshold int
	window    time.Duration
	penalty   time.Duration
}

type bearerFailureEntry struct {
	firstFailureAt time.Time
	penaltyUntil   time.Time
	count          int
}

func newBearerFailureTracker(threshold int, window, penalty time.Duration) *bearerFailureTracker {
	if threshold <= 0 {
		threshold = 20
	}
	if window <= 0 {
		window = 60 * time.Second
	}
	if penalty <= 0 {
		penalty = 60 * time.Second
	}
	return &bearerFailureTracker{
		entries:   make(map[string]*bearerFailureEntry),
		threshold: threshold,
		window:    window,
		penalty:   penalty,
	}
}

// blocked reports whether the source IP is currently in the penalty box.
// Returns (true, retryAfter) when blocked; (false, 0) when allowed.
func (b *bearerFailureTracker) blocked(ip string) (bool, time.Duration) {
	if b == nil || ip == "" {
		return false, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[ip]
	if !ok {
		return false, 0
	}
	now := time.Now()
	if !e.penaltyUntil.IsZero() && now.Before(e.penaltyUntil) {
		return true, time.Until(e.penaltyUntil)
	}
	return false, 0
}

// recordFailure increments the failure counter for the given IP and trips
// the penalty box once threshold-within-window is exceeded.
func (b *bearerFailureTracker) recordFailure(ip string) {
	if b == nil || ip == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	e, ok := b.entries[ip]
	if !ok || now.Sub(e.firstFailureAt) > b.window {
		e = &bearerFailureEntry{firstFailureAt: now}
		b.entries[ip] = e
	}
	e.count++
	if e.count >= b.threshold {
		e.penaltyUntil = now.Add(b.penalty)
	}
}

// recordSuccess clears the failure counter for the given IP after a
// successful bearer auth.
func (b *bearerFailureTracker) recordSuccess(ip string) {
	if b == nil || ip == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[ip]
	if !ok {
		return
	}
	// Preserve an active penalty so a single success cannot wipe an in-effect
	// lockout; only reset the counter when no penalty is active or it has expired.
	now := time.Now()
	if e.penaltyUntil.IsZero() || now.After(e.penaltyUntil) {
		e.count = 0
		e.firstFailureAt = now
	}
}

// clientIPForBearer returns the source IP used to key the failure tracker.
// Trusts only the request's transport-level RemoteAddr; X-Forwarded-For is
// intentionally ignored to avoid attacker-controlled key spoofing. Behind a
// trusted reverse proxy where every request shares one IP, the throttle is
// still useful (caps attacker churn through that proxy) — operators wanting
// per-real-client throttling must terminate at this middleware.
func clientIPForBearer(req *http.Request) string {
	if req == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// --- Bearer auth entrypoint ---

// detectBearerToken returns (token, true) when the request carries a usable
// Authorization: Bearer header. Case-insensitive on the scheme. Returns
// ("", false) for any other shape.
func detectBearerToken(req *http.Request) (string, bool) {
	if req == nil {
		return "", false
	}
	h := req.Header.Get("Authorization")
	if len(h) < len(bearerPrefix) {
		return "", false
	}
	if !strings.EqualFold(h[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(bearerPrefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// hasSessionCookie reports whether the request carries any cookie matching
// the session prefix. Used to implement the cookie-wins-by-default
// precedence rule when both bearer and cookie are present.
func (t *TraefikOidc) hasSessionCookie(req *http.Request) bool {
	if t.sessionManager == nil {
		return false
	}
	prefix := t.sessionManager.GetCookiePrefix()
	if prefix == "" {
		return false
	}
	for _, c := range req.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			return true
		}
	}
	return false
}

// writeBearerError writes the canonical 401/403/429/503 response per spec §9.
// Body is always generic; reason is logged at debug only. The
// WWW-Authenticate hint is gated by config (default on, RFC 6750 compliant).
func (t *TraefikOidc) writeBearerError(rw http.ResponseWriter, req *http.Request, err *bearerError) {
	var (
		status     int
		errCode    string
		body       string
		retryAfter time.Duration
	)
	switch err.kind {
	case bearerErrInvalidRequest:
		status = http.StatusUnauthorized
		errCode = "invalid_request"
		body = "Unauthorized"
	case bearerErrInvalidToken, bearerErrTokenInactive, bearerErrInvalidIdentifier:
		status = http.StatusUnauthorized
		errCode = "invalid_token"
		body = "Unauthorized"
	case bearerErrForbidden:
		status = http.StatusForbidden
		body = "Access denied"
	case bearerErrThrottled:
		status = http.StatusTooManyRequests
		body = "Too Many Requests"
		retryAfter = t.bearerFailurePenalty
	case bearerErrIntrospectionUnavailable:
		status = http.StatusServiceUnavailable
		body = "Service Unavailable"
	default:
		status = http.StatusUnauthorized
		body = "Unauthorized"
	}

	if t.bearerEmitWWWAuthenticate && errCode != "" {
		rw.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q`, errCode))
	}
	if retryAfter > 0 {
		rw.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body)) // Safe to ignore: best-effort error body write

	if t.logger != nil {
		t.logger.Debugf("bearer auth rejected: status=%d category=%v reason=%q path=%s",
			status, err.kind, err.reason, req.URL.Path)
	}
}

// handleBearerRequest is the entry point invoked by ServeHTTP when the
// EnableBearerAuth flag is set, the request carries an Authorization: Bearer
// header, and the (configurable) cookie-precedence rule allows the bearer
// path to run.
func (t *TraefikOidc) handleBearerRequest(rw http.ResponseWriter, req *http.Request) {
	ip := clientIPForBearer(req)

	if blocked, retryAfter := t.bearerFailureTracker.blocked(ip); blocked {
		throttled := newBearerError(bearerErrThrottled, "ip in penalty box")
		// Preserve the actual retry-after even if it diverged from the
		// configured default (clock-skew, partial-window expiry).
		if retryAfter > 0 {
			rw.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		}
		t.writeBearerError(rw, req, throttled)
		return
	}

	token, ok := detectBearerToken(req)
	if !ok {
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, newBearerError(bearerErrInvalidRequest, "missing or empty bearer token"))
		return
	}
	if len(token) > AccessTokenConfig.MaxLength {
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, newBearerError(bearerErrInvalidToken, "token exceeds max length"))
		return
	}
	if strings.Count(token, ".") != 2 {
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, newBearerError(bearerErrInvalidToken, "token is not a 3-segment JWT"))
		return
	}

	if bErr := parseBearerJOSEHeader(token); bErr != nil {
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, bErr)
		return
	}

	p, bErr := t.buildPrincipalFromBearerToken(token)
	if bErr != nil {
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, bErr)
		return
	}

	t.bearerFailureTracker.recordSuccess(ip)
	if t.logger != nil {
		t.logger.Debugf("bearer auth success: identifier_hash=%s path=%s",
			hashIdentifierForLog(p.Identifier), req.URL.Path)
	}
	t.forwardAuthorized(rw, req, p)
}

// buildPrincipalFromBearerToken runs the full bearer verification pipeline
// described in spec §7.3 and returns a principal ready for forwardAuthorized.
// Returns a typed *bearerError on failure so the caller can map to status.
func (t *TraefikOidc) buildPrincipalFromBearerToken(token string) (*principal, *bearerError) {
	if err := t.verifyTokenWithOpts(token, verifyOpts{skipReplayMarking: true}); err != nil {
		return nil, newBearerError(bearerErrInvalidToken, "token verification failed: "+err.Error())
	}

	parsed, err := parseJWT(token)
	if err != nil {
		return nil, newBearerError(bearerErrInvalidToken, "post-verify parseJWT failed: "+err.Error())
	}
	claims := parsed.Claims

	// Token-type guard. Reuse the well-tested classifier which already
	// checks nonce / typ=at+jwt / token_use / scope / aud-vs-clientID.
	if t.detectTokenType(parsed, token) {
		return nil, newBearerError(bearerErrInvalidToken, "ID tokens are not accepted on the bearer path")
	}
	// Belt-and-braces explicit rejection (cheap, catches edge cases not
	// covered by detectTokenType's heuristic).
	if nonce, ok := claims["nonce"].(string); ok && nonce != "" {
		return nil, newBearerError(bearerErrInvalidToken, "nonce claim present (ID-token shape)")
	}
	if tu, ok := claims["token_use"].(string); ok && tu == "id" {
		return nil, newBearerError(bearerErrInvalidToken, "token_use=id rejected")
	}

	if bErr := enforceMultiAudienceAzp(claims, t.clientID); bErr != nil {
		return nil, bErr
	}
	if bErr := enforceIatAge(claims, t.maxTokenAge); bErr != nil {
		return nil, bErr
	}

	if t.requireTokenIntrospection {
		if bErr := t.introspectOnBearerPath(token); bErr != nil {
			return nil, bErr
		}
	}

	rawIdentifier, bErr := resolveBearerIdentifier(claims, t.bearerIdentifierClaim)
	if bErr != nil {
		return nil, bErr
	}
	identifier, bErr := sanitizeBearerIdentifier(rawIdentifier, t.maxIdentifierLength)
	if bErr != nil {
		return nil, bErr
	}

	subject, _ := claims["sub"].(string)
	clientID, _ := claims["azp"].(string)
	if clientID == "" {
		clientID, _ = claims["client_id"].(string)
	}

	return &principal{
		Source:      sourceBearer,
		Identifier:  identifier,
		Subject:     subject,
		ClientID:    clientID,
		Claims:      claims,
		AccessToken: token,
	}, nil
}

// introspectOnBearerPath calls the existing RFC 7662 introspector when the
// operator demands real-time revocation. Distinguishes "token revoked" (401)
// from "endpoint unavailable" (503) so transient infra failures don't look
// like credential failures.
func (t *TraefikOidc) introspectOnBearerPath(token string) *bearerError {
	resp, err := t.introspectToken(token)
	if err != nil {
		return newBearerError(bearerErrIntrospectionUnavailable, "introspection failed: "+err.Error())
	}
	if !resp.Active {
		return newBearerError(bearerErrTokenInactive, "introspection reports token inactive")
	}
	return nil
}
