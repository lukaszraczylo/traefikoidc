package traefikoidc

import (
	"crypto/x509"
	"testing"
)

// TestSharedTransportPoolAtCapPreservesTLS is an R95 regression: when the
// pool is at its client cap and no existing transport was built for the
// requested TLS config, GetOrCreateTransport must still return a properly
// configured transport. Before the fix it returned nil, so the caller fell
// back to http.DefaultTransport and silently dropped the configured
// RootCAs / InsecureSkipVerify (custom-CA TLS broke, self-signed
// skip-verify was lost).
func TestSharedTransportPoolAtCapPreservesTLS(t *testing.T) {
	pool := &SharedTransportPool{
		transports:  make(map[string]*sharedTransport),
		maxClients:  2,
		maxConns:    20,
		clientCount: 0,
	}

	// Fill the pool to the cap (2) with two distinct TLS configs.
	configA := HTTPClientConfig{}
	configB := HTTPClientConfig{RootCAs: x509.NewCertPool()}
	pool.GetOrCreateTransport(configA)
	pool.GetOrCreateTransport(configB)

	// Request a third, distinct TLS config (InsecureSkipVerify) at the cap.
	configC := HTTPClientConfig{InsecureSkipVerify: true} //nolint:gosec // test-only: asserts skip-verify survives at cap
	tr := pool.GetOrCreateTransport(configC)
	if tr == nil {
		t.Fatal("GetOrCreateTransport returned nil at the client cap; TLS config would be silently dropped")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("at-cap transport must preserve the requested InsecureSkipVerify setting")
	}
}
