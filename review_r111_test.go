package traefikoidc

import (
	"fmt"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
)

// testNetError implements net.Error for exercising the retry classifier.
type testNetError struct{ timeout bool }

func (e *testNetError) Error() string   { return "test net error" }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return e.timeout }

// TestIsRetryableError_WrappedTransient regresses RetryExecutor's retry
// classifier using direct type assertions on the top-level error instead of
// errors.As. Transient errors surfaced as fmt.Errorf("...: %w", err) from
// an upstream layer (net timeout, 5xx, 429) were misclassified as
// permanent and never retried, failing on the first attempt. Wrapped
// retryable errors must now be recognized and retried.
func TestIsRetryableError_WrappedTransient(t *testing.T) {
	re := NewRetryExecutor(DefaultRetryConfig(), nil)
	require := require.New(t)

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"wrapped net timeout", fmt.Errorf("upstream call: %w", &testNetError{timeout: true}), true},
		{"wrapped 500", fmt.Errorf("call: %w", &HTTPError{StatusCode: 500}), true},
		{"wrapped 429", fmt.Errorf("call: %w", &HTTPError{StatusCode: 429}), true},
		{"direct 500 (unchanged)", &HTTPError{StatusCode: 500}, true},
		{"direct net timeout (unchanged)", &testNetError{timeout: true}, true},
		{"wrapped 404 permanent", fmt.Errorf("call: %w", &HTTPError{StatusCode: 404}), false},
	}

	for _, c := range cases {
		got := re.isRetryableError(c.err)
		require.Equal(c.want, got, "case %q: got retryable=%v want %v", c.name, got, c.want)
	}
}

// TestSessionAccessors_ConcurrentAccess regresses the 8 simple session
// accessors (Get/SetCSRF, Get/SetNonce, Get/SetCodeVerifier,
// Get/SetIncomingPath) that read/wrote mainSession.Values WITHOUT holding
// sessionMutex while every other accessor (e.g. GetUserIdentifier,
// SetUserIdentifier) does. When two requests share one pooled SessionData
// (the documented pool-aliasing case), concurrent map read/write hits
// mainSession.Values and races/crashes. Run with -race.
func TestSessionAccessors_ConcurrentAccess(t *testing.T) {
	sd := &SessionData{
		mainSession: sessions.NewSession(nil, "main"),
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 20000; i++ {
			sd.SetCSRF("csrf")
			sd.SetNonce("nonce")
			sd.SetCodeVerifier("verifier")
			sd.SetIncomingPath("/protected")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 20000; i++ {
			_ = sd.GetCSRF()
			_ = sd.GetNonce()
			_ = sd.GetCodeVerifier()
			_ = sd.GetIncomingPath()
		}
	}()

	close(start)
	wg.Wait()
}
