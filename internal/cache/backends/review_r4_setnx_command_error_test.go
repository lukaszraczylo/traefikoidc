package backends

// R4 cache review (medium): RedisBackend.SetNX reported
// backends.ErrSetNXAmbiguous for a definitive Redis command-error reply (a
// RESP '-' line such as -READONLY, -OOM or -MISCONF), not only for a
// genuinely lost reply. A command-error reply proves Redis rejected the
// command outright — nothing was applied — so treating it as merely
// "outcome unknown" let checkAndMarkLogoutJTIProcessed accept a logout
// token's jti-claim outright instead of falling through to its process-local
// fallback, so a captured logout token could be replayed indefinitely while
// Redis rejects writes (e.g. a demoted read-only replica after a failover).
//
// errorReplyProxy relays a single TCP connection to a real miniredis
// instance, but answers the FIRST command containing trigger with a
// scripted RESP error line instead of forwarding it to the server —
// modeling Redis actively refusing the write, as opposed to
// review_r2_fix17_setnx_reply_dropped_test.go's dropReplyProxy, which
// forwards the command and only swallows its reply.

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorReplyProxy struct {
	ln      net.Listener
	target  string
	trigger []byte
	errLine []byte

	mu        sync.Mutex
	triggered bool
}

func newErrorReplyProxy(t *testing.T, target string, trigger, errLine []byte) *errorReplyProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	p := &errorReplyProxy{ln: ln, target: target, trigger: trigger, errLine: errLine}
	go p.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *errorReplyProxy) Addr() string { return p.ln.Addr().String() }

func (p *errorReplyProxy) acceptLoop() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(client)
	}
}

func (p *errorReplyProxy) handleConn(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// client -> server: intercept the first command containing trigger and
	// answer it directly with errLine instead of forwarding it, so the
	// command never reaches Redis at all (a definitive rejection, not a
	// lost reply after Redis already applied the write).
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rerr := client.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				p.mu.Lock()
				intercept := !p.triggered && bytes.Contains(chunk, p.trigger)
				if intercept {
					p.triggered = true
				}
				p.mu.Unlock()

				if intercept {
					if _, werr := client.Write(p.errLine); werr != nil {
						break
					}
				} else if _, werr := server.Write(chunk); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = server.Close()
	}()

	// server -> client: relay every real reply unchanged.
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rerr := server.Read(buf)
			if n > 0 {
				if _, werr := client.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = client.Close()
	}()

	wg.Wait()
}

// TestR4_RedisBackendSetNX_CommandErrorReply_ReturnsDefiniteError pins that a
// SET NX rejected outright by Redis (a RESP '-' error reply) is reported as
// a plain, definitive error — never backends.ErrSetNXAmbiguous, which means
// "may have applied, outcome unknown" and is reserved for a reply lost
// after the write (timeout/EOF/reset), a different failure mode entirely.
func TestR4_RedisBackendSetNX_CommandErrorReply_ReturnsDefiniteError(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	proxy := newErrorReplyProxy(t, mr.Addr(), []byte("NX"),
		[]byte("-READONLY You can't write against a read only replica.\r\n"))

	config := DefaultRedisConfig(proxy.Addr())
	config.PoolSize = 1
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	key := "readonly-claim"

	claimed, setNXErr := backend.SetNX(ctx, key, []byte("v1"), time.Minute)

	assert.False(t, claimed, "a rejected SET NX must not report claimed=true")
	require.Error(t, setNXErr, "a Redis command-error reply must surface as an error")
	assert.NotSame(t, ErrSetNXAmbiguous, setNXErr,
		"a definitive Redis rejection (-READONLY/-OOM/-MISCONF) is NOT ambiguous — "+
			"it proves the command was never applied, so it must not be reported "+
			"as ErrSetNXAmbiguous, which tells callers the write may have landed")

	// Confirm directly against miniredis (bypassing the proxy) that the
	// write never applied — the command was answered by the proxy, not
	// forwarded.
	_, verr := mr.Get(config.RedisPrefix + key)
	assert.Error(t, verr, "the rejected SET NX must not have applied in Redis")
}
