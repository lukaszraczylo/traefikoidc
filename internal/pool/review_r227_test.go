package pool

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

// TestTransportPool_TLSMatchesNormalizesDefault covers the previously
// 0%-covered tlsMatches security guard (R146): two transports share the
// pool only when their TLS posture (certificate verification and
// minimum protocol version) matches, with 0 normalized to the TLS1.2
// default that createTransport applies.
func TestTransportPool_TLSMatchesNormalizesDefault(t *testing.T) {
	p := &TransportPool{}

	// 0 (createTransport's default) must be equivalent to explicit TLS1.2.
	if !p.tlsMatches(TransportConfig{}, TransportConfig{MinTLSVersion: tls.VersionTLS12}) {
		t.Fatal("zero and explicit TLS1.2 minimum must match after normalization")
	}

	// Differing verification posture must never match.
	if p.tlsMatches(
		TransportConfig{InsecureSkipVerify: true},
		TransportConfig{InsecureSkipVerify: false},
	) {
		t.Fatal("configs differing in InsecureSkipVerify must not match")
	}

	// Differing minimum TLS version must never match.
	if p.tlsMatches(
		TransportConfig{MinTLSVersion: tls.VersionTLS12},
		TransportConfig{MinTLSVersion: tls.VersionTLS13},
	) {
		t.Fatal("configs differing in MinTLSVersion must not match")
	}
}

// TestTransportPool_NoTLSMismatchReuse drives getExistingTransport
// directly: a strict-verifying caller must never be handed a pooled
// InsecureSkipVerify transport (silent cert-verification bypass, R146);
// it falls back to nil so the caller builds a safe verifying client.
func TestTransportPool_NoTLSMismatchReuse(t *testing.T) {
	p := &TransportPool{
		transports: map[string]*sharedTransport{
			"insecure": {
				transport: &http.Transport{},
				config:    TransportConfig{InsecureSkipVerify: true, MinTLSVersion: tls.VersionTLS12},
				refCount:  0,
				lastUsed:  time.Now(),
			},
			"verifyTLS13": {
				transport: &http.Transport{},
				config:    TransportConfig{InsecureSkipVerify: false, MinTLSVersion: tls.VersionTLS13},
				refCount:  0,
				lastUsed:  time.Now(),
			},
		},
		maxConns:   20,
		maxClients: 100,
	}

	// Strict TLS1.2 caller must NOT reuse the insecure or TLS1.3 peers.
	if tr := p.getExistingTransport(TransportConfig{MinTLSVersion: tls.VersionTLS12}); tr != nil {
		t.Fatal("strict-verifying caller received a mismatched pooled transport")
	}

	// Insecure caller matches the insecure peer and reuses it.
	if tr := p.getExistingTransport(TransportConfig{InsecureSkipVerify: true, MinTLSVersion: tls.VersionTLS12}); tr == nil {
		t.Fatal("insecure caller should reuse the insecure pooled transport")
	}

	// TLS1.3 verifying caller matches the TLS1.3 peer.
	if tr := p.getExistingTransport(TransportConfig{MinTLSVersion: tls.VersionTLS13}); tr == nil {
		t.Fatal("TLS1.3 caller should reuse the TLS1.3 verifying transport")
	}
}
