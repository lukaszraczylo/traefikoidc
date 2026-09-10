package traefikoidc

// R4 cache review (medium), end-to-end companion to internal/cache/backends'
// review_r4_setnx_command_error_test.go: once RedisBackend.SetNX reports a
// definitive Redis command-error reply (-READONLY, -OOM, -MISCONF, ...) as a
// plain error instead of backends.ErrSetNXAmbiguous,
// checkAndMarkLogoutJTIProcessed must fall through to its
// backchannelLogoutJTIMu-guarded Get+Set fallback (see that mutex's comment
// in logout.go) instead of accepting the token outright — and that fallback
// must still reject a replayed jti while every distributed write keeps
// failing the same way, exactly as it did before FIX-17 introduced the
// atomic path. Before the redis.go fix, both calls below returned nil
// (accepted): the atomic branch treated the sustained -READONLY rejection
// as "outcome unknown" and never even reached the fallback, so a captured
// logout token could be replayed indefinitely while Redis rejects writes.

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r4AlwaysReadonlyProxy relays a single TCP connection to a real miniredis
// instance, but answers EVERY write command (SET, SETEX, PSETEX all contain
// "SET") with a scripted -READONLY reply instead of forwarding it — modeling
// a demoted Redis master that keeps rejecting writes for the whole test,
// unlike a proxy that only trips once.
type r4AlwaysReadonlyProxy struct {
	ln     net.Listener
	target string
}

func newR4AlwaysReadonlyProxy(t *testing.T, target string) *r4AlwaysReadonlyProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &r4AlwaysReadonlyProxy{ln: ln, target: target}
	go p.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *r4AlwaysReadonlyProxy) Addr() string { return p.ln.Addr().String() }

func (p *r4AlwaysReadonlyProxy) acceptLoop() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(client)
	}
}

func (p *r4AlwaysReadonlyProxy) handleConn(client net.Conn) {
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
				if bytes.Contains(chunk, []byte("SET")) {
					if _, werr := client.Write([]byte("-READONLY You can't write against a read only replica.\r\n")); werr != nil {
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

func TestR4_CheckAndMarkLogoutJTIProcessed_SustainedReadonlyRedis_RejectsReplay(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	proxy := newR4AlwaysReadonlyProxy(t, mr.Addr())

	cfg := backends.DefaultRedisConfig(proxy.Addr())
	cfg.PoolSize = 1
	redisBackend, err := backends.NewRedisBackend(cfg)
	require.NoError(t, err, "connecting through the proxy must succeed — only SET-family commands are rejected")
	t.Cleanup(func() { _ = redisBackend.Close() })

	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:             CacheTypeSession,
		DefaultTTL:       sessionInvalidationTTL,
		Logger:           NewLogger("error"),
		SkipAutoCleanup:  true,
		MonotonicMarkers: true, // matches the real session-invalidation cache config
	}, redisBackend)
	t.Cleanup(func() { _ = uc.Close() })

	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		sessionInvalidationCache: &CacheInterfaceWrapper{cache: uc, managed: true},
	}

	jti := "r4-e2e-readonly-jti"

	firstErr := oidc.checkAndMarkLogoutJTIProcessed(jti, time.Now().Unix())
	require.NoError(t, firstErr, "the first delivery of a jti must be accepted even while Redis keeps rejecting writes")

	replayErr := oidc.checkAndMarkLogoutJTIProcessed(jti, time.Now().Unix())
	require.Error(t, replayErr,
		"a captured logout token must not be replayable forever just because Redis rejects writes: "+
			"SetNX must not report ErrSetNXAmbiguous for a definitive command-error reply")
	assert.Contains(t, replayErr.Error(), "already processed")
}
