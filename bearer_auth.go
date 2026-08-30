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
	"errors"
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
	// retryAfter carries the actual remaining penalty when known (e.g. the
	// per-IP penalty box), so writeBearerError emits the true value instead
	// of the full configured penalty.
	retryAfter time.Duration
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

// joseHeaderWellFormed reports whether token is structurally a JWT: exactly
// two dot-separated segments whose header decodes as a JSON JOSE header.
// It intentionally applies NO alg/kid policy (unlike parseBearerJOSEHeader)
// so the JWT-vs-opaque routing gate classifies purely on structure: a
// structurally-valid JWT with a disallowed alg stays on the JWT path
// (where local policy rejects it), while an opaque token whose two dots
// are coincidental falls through to opaque introspection (R166).
func joseHeaderWellFormed(token string) bool {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return false
	}
	if strings.Count(token[dot+1:], ".") != 1 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(token[:dot])
		if err != nil {
			return false
		}
	}
	var hdr joseHeader
	return json.Unmarshal(raw, &hdr) == nil
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

// headerClaimRuneReason reports why a rune is unsafe to inject into a request
// header value, or "" if the rune is acceptable. Shared core of the bearer-path
// identifier sanitizer and the cookie-path header claim sanitizer: rejects
// control chars (CRLF/header injection), Unicode bidi-override runes (RTL
// spoofing of admin UI / SIEM), and the delimiters , ; = plus the bracketing
// characters " { } — each of these in a group name / identifier would break a
// downstream comma-joined list or a naive CSV/JSON-style parser consuming the
// header (a comma would inject extra entries into a comma-joined header).
func headerClaimRuneReason(r rune) string {
	if reason := headerInjectionRuneReason(r); reason != "" {
		return reason
	}
	// The , ; = delimiters and the " { } bracketing chars are only unsafe for
	// values placed into delimited or list contexts (a comma-joined header, or
	// an identifier downstreams may split). They are valid in arbitrary single
	// header values, so this stricter check is used for the cookie-path
	// identifier and the group/role list, NOT for free-form templated header
	// output (see headerValueReason).
	if r == ',' || r == ';' || r == '=' || r == '"' || r == '{' || r == '}' {
		return "delimiter or bracketing character"
	}
	return ""
}

// headerInjectionRuneReason reports why a rune is unsafe in ANY HTTP header
// value, or "" if acceptable. Rejects control characters (CR/LF header
// injection) and Unicode bidi-override runes (RTL spoofing of admin UIs/SIEMs).
// Unlike headerClaimRuneReason it does NOT reject , ; = which are legitimate in
// free-form header values (e.g. an opaque "Authorization: Bearer <token>").
func headerInjectionRuneReason(r rune) string {
	if unicode.IsControl(r) {
		return "control character"
	}
	if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
		return "bidi-override character"
	}
	return ""
}

// headerValueReason reports why value is unsafe to forward as a free-form HTTP
// header value, or "" if acceptable. It rejects values over maxLen (maxLen<=0
// disables the check) and values containing control or bidi-override runes, but
// permits , ; = (valid in header values). Empty is allowed. The reason string
// never includes the value, so it is safe to log.
func headerValueReason(value string, maxLen int) string {
	if maxLen > 0 && len(value) > maxLen {
		return "exceeds max length"
	}
	for _, r := range value {
		if reason := headerInjectionRuneReason(r); reason != "" {
			return reason
		}
	}
	return ""
}

// headerClaimValueReason reports why value is unsafe to inject into a
// downstream request header, or "" if it is acceptable. It rejects empty
// values, values exceeding maxLen (maxLen<=0 disables the length check), and
// values containing any rune rejected by headerClaimRuneReason. The reason
// string is safe to log (it never includes the value itself).
func headerClaimValueReason(value string, maxLen int) string {
	if value == "" {
		return "empty value"
	}
	if maxLen > 0 && len(value) > maxLen {
		return "exceeds max length"
	}
	for _, r := range value {
		if reason := headerClaimRuneReason(r); reason != "" {
			return reason
		}
	}
	return ""
}

// sanitizeHeaderClaimValue validates a claim-derived value before it is
// injected into a downstream request header. It trims surrounding whitespace
// and fails closed (ok=false) on empty values, values exceeding maxLen
// (maxLen<=0 disables the length check), or values containing any rune rejected
// by headerClaimRuneReason. Used by the cookie/session path, which — unlike the
// bearer path — does not otherwise sanitize the principal identifier or the
// group/role strings joined into X-User-Groups / X-User-Roles.
func sanitizeHeaderClaimValue(raw string, maxLen int) (string, bool) {
	value := strings.TrimSpace(raw)
	if headerClaimValueReason(value, maxLen) != "" {
		return "", false
	}
	return value, true
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
		if reason := headerClaimRuneReason(r); reason != "" {
			return "", newBearerError(bearerErrInvalidIdentifier, "identifier contains "+reason)
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
	// Accept scalar numbers (e.g. a numeric sub) by stringifying them,
	// so a numeric identifier claim doesn't 401 a valid principal.
	if s, isScalar := claimScalarString(raw); isScalar {
		return s, nil
	}
	return "", newBearerError(bearerErrInvalidIdentifier, fmt.Sprintf("claim %q is not a scalar string or number", claimName))
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

// defaultBearerEntrySweepThreshold is the map size above which recordFailure
// sweeps stale entries, bounding memory under a flood of distinct source IPs.
const defaultBearerEntrySweepThreshold = 1024

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
	// Bound per-IP map growth (R117): entries for source IPs that fail once
	// and never return were never removed. Sweep stale entries (no active
	// penalty box, too old to matter) once the map grows past a nominal
	// size, keeping steady-state memory bounded.
	if len(b.entries) > defaultBearerEntrySweepThreshold {
		cutoff := now.Add(-(b.window + b.penalty))
		for k, e := range b.entries {
			if e.penaltyUntil.Before(cutoff) {
				delete(b.entries, k)
			}
		}
	}
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
		retryAfter = err.retryAfter
		if retryAfter <= 0 {
			retryAfter = t.bearerFailurePenalty
		}
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
	// Auth-rejection responses must never be cached (R101 contract): a
	// cached 429/401 could be replayed to a client well after the
	// penalty box expired or the session recovered.
	rw.Header().Set("Cache-Control", "no-store")
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
		// Carry the actual remaining penalty (diverges from the configured
		// default on clock-skew, partial-window expiry) so writeBearerError
		// emits the true Retry-After rather than the full penalty.
		throttled := newBearerError(bearerErrThrottled, "ip in penalty box")
		throttled.retryAfter = retryAfter
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
	// Determine whether this is genuinely a JWT. RFC 7662 token
	// introspection covers opaque access tokens; when the operator
	// requires live introspection (requireTokenIntrospection, whose
	// documented purpose is exactly opaque-token support via
	// client_secret_basic), introspect the opaque token on the bearer
	// path instead of rejecting it — the session path already does
	// (validateOpaqueToken). Previously the JWT-shape gate ran before
	// the introspection branch, so every opaque token got a 401 even
	// with introspection on (R159).
	//
	// A token is only treated as a JWT when it has exactly two dots AND
	// its header actually parses as a JOSE header. Dot count alone is
	// insufficient: an opaque token that coincidentally contains exactly
	// two dots used to be routed onto the JWT path and rejected even
	// under requireTokenIntrospection (header parse would fail) — it must
	// instead be introspected like any other opaque token (R166).
	isJWT := joseHeaderWellFormed(token)
	if !isJWT {
		if t.requireTokenIntrospection {
			p, bErr := t.buildPrincipalFromOpaqueIntrospection(token)
			if bErr != nil {
				if bErr.kind != bearerErrIntrospectionUnavailable {
					t.bearerFailureTracker.recordFailure(ip)
				}
				t.writeBearerError(rw, req, bErr)
				return
			}
			t.bearerFailureTracker.recordSuccess(ip)
			if t.logger != nil {
				t.logger.Debugf("bearer auth success (introspected opaque): identifier_hash=%s path=%s",
					hashIdentifierForLog(p.Identifier), req.URL.Path)
			}
			t.forwardAuthorized(rw, req, p)
			return
		}
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, newBearerError(bearerErrInvalidToken, "token is not a valid JWT"))
		return
	}

	// Structurally a JWT: enforce the alg/kid policy EARLY (before the
	// cached fast-path in buildPrincipalFromBearerToken can short-circuit
	// on a prior positive verdict). Without this pin an alg=none or
	// oversized-kid token that had been cached as verified would sail
	// through without re-checking.
	if bErr := parseBearerJOSEHeader(token); bErr != nil {
		t.bearerFailureTracker.recordFailure(ip)
		t.writeBearerError(rw, req, bErr)
		return
	}

	p, bErr := t.buildPrincipalFromBearerToken(token)
	if bErr != nil {
		// Count only authentication failures (401/403) toward the per-IP
		// throttle. An introspection outage (503) is infrastructure, not a
		// client failure; recording it would trip a 429 penalty that a
		// single success can't clear even after the endpoint recovers.
		if bErr.kind != bearerErrIntrospectionUnavailable {
			t.bearerFailureTracker.recordFailure(ip)
		}
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

	// Snapshot clientID under metadataMu: DCR rewrites it at runtime (R137).
	clientID, _, _, _, _ := t.clientCredentials()
	if bErr := enforceMultiAudienceAzp(claims, clientID); bErr != nil {
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

	// Honor IdP-initiated (backchannel/front-channel) logout. The cookie
	// path re-checks sessionInvalidationCache on every request; the bearer
	// path previously did not, so a still-cryptographically-valid access
	// token for a logged-out subject kept returning 200 (and, with
	// requireTokenIntrospection, a cached positive verdict extended the
	// stale window). Reject here, mirroring the cookie path: use the
	// token's iat as its creation time so a token issued before the
	// logout is invalidated, while a legitimately freshly-issued token
	// (iat after logout) still passes (R146).
	subjectForInvalidation, _ := claims["sub"].(string)
	sidForInvalidation, _ := claims["sid"].(string)
	createdAt := time.Now()
	if iat, ok := claims["iat"].(float64); ok {
		createdAt = time.Unix(int64(iat), 0)
	}
	if t.isSessionInvalidated(sidForInvalidation, subjectForInvalidation, createdAt) {
		return nil, newBearerError(bearerErrInvalidToken, "session has been invalidated (logout)")
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
	clientID, _ = claims["azp"].(string)
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

// buildPrincipalFromOpaqueIntrospection authenticates a bearer access
// token that has no JWT shape by live RFC 7662 introspection, and builds
// a principal whose identifier is the introspected subject. It mirrors
// introspectOnBearerPath's classification (active, token_type, expiry,
// audience) and binds the compliant subject. Only used on the bearer
// path when requireTokenIntrospection is enabled (R159).
func (t *TraefikOidc) buildPrincipalFromOpaqueIntrospection(token string) (*principal, *bearerError) {
	resp, err := t.introspectToken(token)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
			return nil, newBearerError(bearerErrTokenInactive, fmt.Sprintf("introspection reports token inactive (HTTP %d)", httpErr.StatusCode))
		}
		return nil, newBearerError(bearerErrIntrospectionUnavailable, "introspection failed: "+err.Error())
	}
	if !resp.Active {
		return nil, newBearerError(bearerErrTokenInactive, "introspection reports token inactive")
	}
	// Mirror introspectOnBearerPath (R149): reject a definite non-access
	// token_type (e.g. refresh_token); accept "access_token" and "Bearer".
	if resp.TokenType != "" && resp.TokenType != "access_token" && resp.TokenType != "Bearer" {
		return nil, newBearerError(bearerErrTokenInactive, "introspection token_type is not a bearer access token")
	}
	if resp.Exp > 0 && time.Now().After(time.Unix(resp.Exp, 0)) {
		return nil, newBearerError(bearerErrTokenInactive, "introspection reports token expired")
	}
	// Audience gate when a distinct API audience is configured.
	clientID, _, _, audience, _ := t.clientCredentials()
	if audience != "" && audience != clientID {
		if resp.Aud == nil || verifyAudience(resp.Aud, audience) != nil {
			return nil, newBearerError(bearerErrTokenInactive, "introspection audience mismatch")
		}
	}
	id := resp.Sub
	if id == "" {
		id = resp.Username
	}
	if id == "" {
		return nil, newBearerError(bearerErrInvalidToken, "introspection response has no subject or username")
	}
	claims := map[string]interface{}{}
	if resp.Sub != "" {
		claims["sub"] = resp.Sub
	}
	if resp.Username != "" {
		claims["username"] = resp.Username
	}
	return &principal{
		Claims:      claims,
		Identifier:  id,
		Subject:     resp.Sub,
		AccessToken: token,
		Source:      sourceBearer,
	}, nil
}

// introspectOnBearerPath calls the existing RFC 7662 introspector when the
// operator demands real-time revocation. Distinguishes "token revoked" (401)
// from "endpoint unavailable" (503) so transient infra failures don't look
// like credential failures.
func (t *TraefikOidc) introspectOnBearerPath(token string) *bearerError {
	resp, err := t.introspectToken(token)
	if err != nil {
		// A definitive 4xx from the introspection endpoint (e.g. 401 for
		// an unknown/revoked token) is a credential failure, not an infra
		// outage — don't downgrade it to "unavailable" (R156).
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
			return newBearerError(bearerErrTokenInactive, fmt.Sprintf("introspection reports token inactive (HTTP %d)", httpErr.StatusCode))
		}
		return newBearerError(bearerErrIntrospectionUnavailable, "introspection failed: "+err.Error())
	}
	if !resp.Active {
		return newBearerError(bearerErrTokenInactive, "introspection reports token inactive")
	}
	// Mirror the session path (validateOpaqueToken): an opaque-or-any
	// token whose RFC 7662 token_type classifies it as a refresh token
	// must not be honored as a bearer access token (R149). Only reject on
	// a definite non-access match; compliant providers may omit it. RFC
	// 7662's token_type is the RFC 6749 token type, whose value for an
	// access token is "Bearer" (RFC 6750) — accept both spellings
	// providers use (R156).
	if resp.TokenType != "" && resp.TokenType != "access_token" && resp.TokenType != "Bearer" {
		return newBearerError(bearerErrTokenInactive, "introspection token_type is not a bearer access token")
	}
	// Mirror the session path (validateOpaqueToken): an active but
	// already-expired result must not pass. The positive-only cache is
	// capped by time-until-exp when Exp is present, but a provider
	// returning active=1 past exp would otherwise let the token pass on
	// the bearer path while the identical token is rejected on the
	// session path.
	if resp.Exp > 0 {
		expTime := time.Unix(resp.Exp, 0)
		if time.Now().After(expTime) {
			return newBearerError(bearerErrTokenInactive, "introspection reports token expired")
		}
	}
	// Mirror the session path (validateOpaqueToken): when a distinct API
	// audience is configured (audience != clientID), the introspection
	// response MUST carry a matching audience. Fail closed on a missing or
	// mismatched aud, otherwise a token minted for a different audience
	// would pass the bearer path while the identical token is rejected on
	// the session path. aud may be a single string or an array (RFC 7662).
	// (R143)
	clientID, _, _, audience, _ := t.clientCredentials()
	if audience != "" && audience != clientID {
		if resp.Aud == nil {
			return newBearerError(bearerErrTokenInactive, "introspection reports no audience")
		}
		if err := verifyAudience(resp.Aud, audience); err != nil {
			return newBearerError(bearerErrTokenInactive, "introspection audience mismatch")
		}
	}
	return nil
}
