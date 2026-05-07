package backends

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drainRESPRequest consumes a single RESP request (array or inline) from r and
// returns true on success. Any read error returns false.
func drainRESPRequest(r *bufio.Reader) bool {
	header, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	if !strings.HasPrefix(header, "*") {
		return true // inline command (single line) — already consumed
	}
	n, err := strconv.Atoi(strings.TrimRight(strings.TrimPrefix(header, "*"), "\r\n"))
	if err != nil || n <= 0 {
		return false
	}
	for i := 0; i < n; i++ {
		// Each bulk: "$len\r\n<bytes>\r\n"
		if _, err := r.ReadString('\n'); err != nil {
			return false
		}
		if _, err := r.ReadString('\n'); err != nil {
			return false
		}
	}
	return true
}

// startTLSPingServer spins up a TLS listener that speaks just enough RESP to
// answer PING with +PONG. Returns the listener address and a self-signed cert.
func startTLSPingServer(t *testing.T) (addr string, certPEM []byte, stop func()) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					if !drainRESPRequest(reader) {
						return
					}
					_, _ = conn.Write([]byte("+PONG\r\n"))
				}
			}(c)
		}
	}()

	stop = func() {
		close(stopCh)
		_ = listener.Close()
		wg.Wait()
	}
	return listener.Addr().String(), der, stop
}

// TestConnectionPool_TLSDial_SkipVerify verifies that EnableTLS=true with
// TLSSkipVerify=true successfully negotiates TLS and exchanges a Redis command.
// Regression test for issue #133 (enableTLS not propagated to client).
func TestConnectionPool_TLSDial_SkipVerify(t *testing.T) {
	addr, _, stop := startTLSPingServer(t)
	defer stop()

	pool, err := NewConnectionPool(&PoolConfig{
		Address:        addr,
		MaxConnections: 2,
		ConnectTimeout: 2 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		EnableTLS:      true,
		TLSSkipVerify:  true,
	})
	require.NoError(t, err)
	defer pool.Close()

	conn, err := pool.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer pool.Put(conn)

	resp, err := conn.Do("PING")
	require.NoError(t, err)
	assert.Equal(t, "PONG", resp)
}

// TestConnectionPool_TLSDial_VerifyFails verifies that EnableTLS=true with
// TLSSkipVerify=false rejects a self-signed server cert.
func TestConnectionPool_TLSDial_VerifyFails(t *testing.T) {
	addr, _, stop := startTLSPingServer(t)
	defer stop()

	pool, err := NewConnectionPool(&PoolConfig{
		Address:        addr,
		MaxConnections: 2,
		ConnectTimeout: 2 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		EnableTLS:      true,
		TLSSkipVerify:  false,
	})
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Get(context.Background())
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "tls")
}

// TestConnectionPool_TLSDial_PlainServerRejected verifies that EnableTLS=true
// fails to handshake against a plain (non-TLS) listener.
func TestConnectionPool_TLSDial_PlainServerRejected(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer plain.Close()

	go func() {
		for {
			c, acceptErr := plain.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	pool, err := NewConnectionPool(&PoolConfig{
		Address:        plain.Addr().String(),
		MaxConnections: 1,
		ConnectTimeout: 1 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		EnableTLS:      true,
		TLSSkipVerify:  true,
	})
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Get(context.Background())
	require.Error(t, err)
}

// TestConnectionPool_PlainDial_StillWorks ensures non-TLS path is unaffected
// when EnableTLS=false (default).
func TestConnectionPool_PlainDial_StillWorks(t *testing.T) {
	mr := NewMiniredisServer(t)

	pool, err := NewConnectionPool(&PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 1,
		ConnectTimeout: 2 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		EnableTLS:      false,
	})
	require.NoError(t, err)
	defer pool.Close()

	conn, err := pool.Get(context.Background())
	require.NoError(t, err)
	defer pool.Put(conn)

	resp, err := conn.Do("PING")
	require.NoError(t, err)
	assert.Equal(t, "PONG", resp)
}
