package traefikoidc

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-3 verifier regression (FIX-17, major): RedisBackend.SetNX checked
// ctx.Err() BEFORE the `if sent` branch that reports ErrSetNXAmbiguous.
// UniversalCache.setIfAbsentBackend gives SetNX a 500ms context, and the
// pool's per-command read deadline is also 500ms (set right after the
// write). So when a SET NX reply is lost, both deadlines expire at roughly
// the same instant, and the (buggy) ctx.Err() check — reached first — wins
// the race almost every time, returning context.DeadlineExceeded instead of
// ErrSetNXAmbiguous.
//
// checkAndMarkLogoutJTIProcessed only special-cases err ==
// backends.ErrSetNXAmbiguous (compared with ==, per FIX-17's "never wrap"
// contract — wrapping with %w or comparing with errors.As breaks under
// yaegi v0.16.1). Any other SetIfAbsent error falls through to the
// mutex-guarded Get+Set fallback, whose Get finds THIS call's own possible
// write and misreports a first-ever, never-before-seen logout token as a
// replay.
//
// Reproducing the buggy ordering deterministically needs two independent
// pieces:
//
//  1. dropReplyProxyR3 sits between the client and a real miniredis
//     instance, forwarding every byte in both directions except the reply
//     to the SET ... NX command, which it swallows entirely — simulating a
//     lost reply after Redis already processed the write (sent=true,
//     doErr=a local read-timeout error).
//
//  2. delayedSetNXBackend wraps the real RedisBackend and sleeps a fixed,
//     large fraction of the 500ms ctx budget BEFORE calling the real
//     SetNX. Without this, the write happens only microseconds after ctx
//     is created, so the local read deadline (500ms after the write)
//     expires only microseconds after ctx's own deadline (500ms after ctx
//     started) — a race so close that RedisBackend's own background
//     connection-health-check PING (always on; ConnectionPool.Get
//     validates a pooled connection with a synchronous PING before handing
//     it back) can tip it either way depending on scheduling, making the
//     reproduction flaky. Sleeping first, inside the SAME goroutine that
//     will call SetNX, pushes the write comfortably later relative to
//     ctx's start with no dependency on background timing at all: by the
//     time the dropped-reply read times out, ctx has been expired for a
//     large, deterministic margin.
type dropReplyProxyR3 struct {
	ln     net.Listener
	target string

	mu         sync.Mutex
	nxSeen     bool
	dropNextNX bool
}

func newDropReplyProxyR3(t *testing.T, target string) *dropReplyProxyR3 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	p := &dropReplyProxyR3{ln: ln, target: target}
	go p.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *dropReplyProxyR3) Addr() string { return p.ln.Addr().String() }

func (p *dropReplyProxyR3) acceptLoop() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(client)
	}
}

func (p *dropReplyProxyR3) handleConn(client net.Conn) {
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
				if !p.nxSeen && bytes.Contains(chunk, []byte("NX")) {
					p.nxSeen = true
					p.dropNextNX = true
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
				drop := p.dropNextNX
				p.dropNextNX = false
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

// setNXStartDelayR3 is how long delayedSetNXBackend sleeps before calling
// the real RedisBackend.SetNX. It must leave enough of the 500ms ctx
// budget for pool.Get + the write to complete (both are fast local/loopback
// operations, on the order of low milliseconds), while being large enough
// that the margin it creates (see delayedSetNXBackend's doc) swamps any
// plausible scheduling jitter.
const setNXStartDelayR3 = 450 * time.Millisecond

// delayedSetNXBackend wraps a real *backends.RedisBackend, embedding it so
// every backends.CacheBackend method (and the optional backendSetNXer
// primitive UniversalCache.SetIfAbsent reaches through a type assertion)
// still delegates to the real implementation — except SetNX, which this
// type overrides to sleep setNXStartDelayR3 first. See the package-level
// comment above for why this determinism trick is needed instead of relying
// on the real 500ms ctx timing alone.
type delayedSetNXBackend struct {
	*backends.RedisBackend
}

func (d *delayedSetNXBackend) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	time.Sleep(setNXStartDelayR3)
	return d.RedisBackend.SetNX(ctx, key, value, ttl)
}

// newFIX17R3DelayedBackendBehindProxy starts a fresh miniredis instance and
// a dropReplyProxyR3 in front of it, and returns a delayedSetNXBackend
// wrapping a RedisBackend pointed at the proxy.
func newFIX17R3DelayedBackendBehindProxy(t *testing.T) (*delayedSetNXBackend, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	proxy := newDropReplyProxyR3(t, mr.Addr())

	config := backends.DefaultRedisConfig(proxy.Addr())
	config.PoolSize = 2
	backend, err := backends.NewRedisBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	return &delayedSetNXBackend{RedisBackend: backend}, mr
}

// TestFIX17R3_UniversalCacheSetIfAbsent_ReplyDropped_ReturnsAmbiguousErr pins
// that UniversalCache.SetIfAbsent surfaces backends.ErrSetNXAmbiguous — not
// context.DeadlineExceeded — when the SET NX reply is lost under the real
// 500ms context setIfAbsentBackend uses. Before the fix, RedisBackend.SetNX
// checked ctx.Err() ahead of the `sent` check, so this returned
// context.DeadlineExceeded instead, indistinguishable to the caller from a
// plain backend timeout.
func TestFIX17R3_UniversalCacheSetIfAbsent_ReplyDropped_ReturnsAmbiguousErr(t *testing.T) {
	backend, mr := newFIX17R3DelayedBackendBehindProxy(t)

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, backend)
	t.Cleanup(func() { _ = cache.Close() })

	claimed, err := cache.SetIfAbsent("r3-ambiguous-key", "v1", time.Minute)

	assert.False(t, claimed, "an ambiguous SetIfAbsent outcome must not report claimed=true")
	require.Error(t, err)
	assert.True(t, err == backends.ErrSetNXAmbiguous, //nolint:staticcheck // intentional == comparison: callers must compare this sentinel with ==, never errors.Is/As, which break under yaegi v0.16.1
		"a lost SET NX reply must surface as backends.ErrSetNXAmbiguous, not %v (e.g. context.DeadlineExceeded)", err)
	assert.NotEmpty(t, mr.Keys(), "the SET NX must have actually reached Redis despite the dropped reply — this is what makes the ambiguity real rather than a plain failure")
}

// TestFIX17R3_CheckAndMarkLogoutJTIProcessed_ReplyDropped_FirstEverJTIAccepted
// pins the end-to-end consequence for logout.go: a first-ever, never-before
// seen backchannel-logout jti must NOT be rejected as a replay when its
// underlying SET NX reply is lost. Before the fix, SetNX's misreported
// context.DeadlineExceeded (instead of ErrSetNXAmbiguous) fell through
// checkAndMarkLogoutJTIProcessed's special case straight into the
// mutex-guarded Get+Set fallback, whose Get found this call's own write
// (the SET NX had actually landed in Redis despite the dropped reply) and
// reported "logout token replay" for a token nobody had ever submitted
// before.
func TestFIX17R3_CheckAndMarkLogoutJTIProcessed_ReplyDropped_FirstEverJTIAccepted(t *testing.T) {
	backend, _ := newFIX17R3DelayedBackendBehindProxy(t)

	wrapper := &CacheInterfaceWrapper{cache: NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, backend)}
	t.Cleanup(wrapper.Close)

	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		sessionInvalidationCache: wrapper,
	}

	err := oidc.checkAndMarkLogoutJTIProcessed("r3-first-ever-jti", time.Now().Unix())

	assert.NoError(t, err, "a first-ever jti must be accepted even when its SET NX reply is lost, not rejected as a replay")
}
