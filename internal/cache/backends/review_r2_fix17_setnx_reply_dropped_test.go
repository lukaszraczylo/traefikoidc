package backends

// Round-2 verifier regression (minor): RedisBackend.SetNX ran the Redis
// SET key value NX PX command inside the shared executeWithRetry helper,
// which blindly retries on a "connection"/"timeout"/"EOF" error by
// re-issuing the whole operation closure. That is safe for Set (SETEX/
// PSETEX overwrite unconditionally, so a retry after a lost reply is a
// no-op repeat), but not for SET NX: if the first SET NX reached Redis and
// applied, but its reply was lost before SetNX could read it, a retried
// SET NX sees the caller's OWN write and reports (false, nil) —
// "already claimed" — for what was actually a first-ever claim.
//
// dropReplyProxy below sits between the client and a real miniredis
// instance, forwarding every request but swallowing the reply to exactly
// one triggering command, reproducing that lost-reply window
// deterministically.

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

// dropReplyProxy relays a single TCP connection to target, forwarding every
// byte in both directions except: the first server->client chunk that
// follows the FIRST client->server chunk containing trigger is swallowed
// instead of forwarded, simulating a reply lost after Redis already
// processed the command. Only the first occurrence of trigger arms a drop —
// a caller's retry re-sending the same command (which necessarily contains
// the same trigger substring) must relay normally, or the test could never
// distinguish "retried and got a real answer" from "every attempt starved".
type dropReplyProxy struct {
	ln      net.Listener
	target  string
	trigger []byte

	mu        sync.Mutex
	triggered bool
	dropNext  bool
}

func newDropReplyProxy(t *testing.T, target string, trigger []byte) *dropReplyProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	p := &dropReplyProxy{ln: ln, target: target, trigger: trigger}
	go p.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *dropReplyProxy) Addr() string { return p.ln.Addr().String() }

func (p *dropReplyProxy) acceptLoop() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(client)
	}
}

func (p *dropReplyProxy) handleConn(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rerr := client.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				p.mu.Lock()
				if !p.triggered && bytes.Contains(chunk, p.trigger) {
					p.triggered = true
					p.dropNext = true
				}
				p.mu.Unlock()
				if _, werr := server.Write(chunk); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = server.Close()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, rerr := server.Read(buf)
			if n > 0 {
				p.mu.Lock()
				drop := p.dropNext
				p.dropNext = false
				p.mu.Unlock()

				if !drop {
					if _, werr := client.Write(buf[:n]); werr != nil {
						break
					}
				}
				// drop == true: swallow this chunk, simulating a lost reply.
			}
			if rerr != nil {
				break
			}
		}
		_ = client.Close()
	}()

	wg.Wait()
}

// TestFIX17R2_RedisBackendSetNX_ReplyDropped_ReportsAmbiguousNotFalseClaim
// pins that a SET NX whose reply is lost after the command reached Redis
// must not be reported as (false, nil) — that reads as "someone else
// already claimed it" when in fact THIS call may have (and, per the proxy,
// did) claim it. It must instead report the request outcome as unknown
// (ErrSetNXAmbiguous), and the key must actually exist in Redis (proving
// the write really landed, so treating it as "not claimed" would have been
// a false negative on a first-ever claim).
func TestFIX17R2_RedisBackendSetNX_ReplyDropped_ReportsAmbiguousNotFalseClaim(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	proxy := newDropReplyProxy(t, mr.Addr(), []byte("NX"))

	config := DefaultRedisConfig(proxy.Addr())
	config.PoolSize = 1
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	key := "first-claim"

	claimed, setNXErr := backend.SetNX(ctx, key, []byte("v1"), time.Minute)

	assert.False(t, claimed, "an ambiguous SetNX outcome must not report claimed=true")
	require.Error(t, setNXErr, "a lost SET NX reply must surface as an error, not (false, nil) — nil reads as \"someone else already claimed it\"")
	assert.Same(t, ErrSetNXAmbiguous, setNXErr, "a lost SET NX reply must surface as the ambiguous sentinel specifically")

	// Confirm directly against miniredis (bypassing the proxy) that the
	// write actually landed — this is what makes (false, nil) wrong: it
	// would have told the caller "not claimed" about a key Redis already
	// holds.
	val, verr := mr.Get(config.RedisPrefix + key)
	require.NoError(t, verr)
	assert.Equal(t, "v1", val, "the SET NX must have actually applied in Redis despite the dropped reply")
}
