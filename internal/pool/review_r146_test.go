package pool

import (
	"crypto/tls"
	"testing"
	"time"
)

// TestTransportPool_ConfigKeyDistinguishesMinTLSVersion guards the R146
// fix in internal/pool/transport.go configKey: the key previously
// omitted MinTLSVersion (and all timeouts), so two configs differing
// only in the TLS minimum version collided on one key and silently
// shared a single transport with whoever-arrived-first's settings — a
// possible TLS-version downgrade. Distinct TLS minimum versions must
// yield non-shared transports with the requested MinVersion.
func TestTransportPool_ConfigKeyDistinguishesMinTLSVersion(t *testing.T) {
	p := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		clientCount: 0,
		maxClients:  100, // high so the at-cap path isn't taken
	}

	cfg12 := TransportConfig{MinTLSVersion: tls.VersionTLS12}
	cfg13 := TransportConfig{MinTLSVersion: tls.VersionTLS13}

	a := p.GetTransport(cfg12)
	b := p.GetTransport(cfg13)

	if a == b {
		t.Fatal("two configs differing only in MinTLSVersion must not share a transport")
	}
	if a.TLSClientConfig == nil || a.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("transport A must use TLS1.2, got %+v", a.TLSClientConfig)
	}
	if b.TLSClientConfig == nil || b.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("transport B must use TLS1.3, got %+v", b.TLSClientConfig)
	}
}

// TestTransportPool_ConfigKeyDistinguishesTimeouts guards the R146 fix
// for the timeout fields: configs differing only in a timeout must not
// collide and share one transport.
func TestTransportPool_ConfigKeyDistinguishesTimeouts(t *testing.T) {
	p := &TransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		clientCount: 0,
		maxClients:  100,
	}

	cfgFast := TransportConfig{MinTLSVersion: tls.VersionTLS12, DialTimeout: time.Second}
	cfgSlow := TransportConfig{MinTLSVersion: tls.VersionTLS12, DialTimeout: 30 * time.Second}

	a := p.GetTransport(cfgFast)
	b := p.GetTransport(cfgSlow)

	if a == nil || b == nil {
		t.Fatal("both transports must be created")
	}
	if a == b {
		t.Fatal("two configs differing only in DialTimeout must not share a transport")
	}
}
