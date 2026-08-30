package traefikoidc

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// perSourceAuthEntry is one source's throttling state, retained briefly
// after last use then evicted so a handful of spoofed X-Forwarded-For
// values can't grow the map unboundedly.
type perSourceAuthEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// perSourceAuthLimiter rate-limits OIDC authentication events per client
// source (external IP). Internal (private / loopback / link-local /
// unspecified) sources are trusted and never throttled, so a reverse
// proxy or in-cluster caller is unbounded while a single external host
// roughly generating many authorize callbacks or login initiations can't
// degrade the shared token-origin token bucket for every user (R185).
type perSourceAuthLimiter struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	entries   map[string]*perSourceAuthEntry
	lastSweep time.Time
}

func newPerSourceAuthLimiter(perMinute int) *perSourceAuthLimiter {
	if perMinute <= 0 {
		return nil // disabled
	}
	return &perSourceAuthLimiter{
		limit:     rate.Limit(float64(perMinute) / 60.0),
		burst:     perMinute,
		entries:   make(map[string]*perSourceAuthEntry),
		lastSweep: time.Now(),
	}
}

// allow reports whether the request's source may proceed (true = allowed).
func (l *perSourceAuthLimiter) allow(req *http.Request) bool {
	ip := sourceIP(req)
	if ip == "" {
		return true // cannot determine source; do not block
	}
	if isInternalSource(ip) {
		// Trusted source (loopback / RFC 1918 / ULA / link-local /
		// unspecified): a reverse proxy or in-cluster caller, never
		// throttled.
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= time.Minute {
		l.sweep(now)
	}
	e := l.entries[ip]
	if e == nil {
		e = &perSourceAuthEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[ip] = e
	}
	e.lastSeen = now
	return e.limiter.Allow()
}

// sweep evicts entries idle for over 10 minutes to bound memory.
func (l *perSourceAuthLimiter) sweep(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > 10*time.Minute {
			delete(l.entries, k)
		}
	}
	l.lastSweep = now
}

// sourceIP returns the client source IP, preferring the first
// X-Forwarded-For value (original client in a proxy chain behind Traefik)
// with RemoteAddr as fallback. Returns "" if none is parseable.
func sourceIP(req *http.Request) string {
	if req == nil {
		return ""
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
			return ip.String()
		}
	}
	if req.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// isInternalSource reports whether ip is loopback, private (RFC 1918 /
// ULA), link-local, or unspecified — i.e. a trusted in-cluster source.
func isInternalSource(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() ||
		p.IsLinkLocalMulticast() || p.IsUnspecified()
}
