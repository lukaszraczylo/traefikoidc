package traefikoidc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// Review regression: the RateLimit config is documented as "requests per
// second" (default 100). The plugin must honor it as the sustained token
// rate, not silently cap sustained throughput at 1 rps by using the value
// only as burst with a fixed rate.Every(time.Second) refill.
func TestRateLimitConfigSetsSustainedRate(t *testing.T) {
	require := require.New(t)

	cfg := &Config{
		ProviderURL:          "https://accounts.google.com",
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "/callback",
		SessionEncryptionKey: "this-is-a-valid-session-key-32b!",
		RateLimit:            50,
	}

	p, err := NewWithContext(context.Background(), cfg, nil, "test")
	require.NoError(err)
	defer p.Close()

	// The configured requests-per-second must be the limiter's actual rate,
	// with a matching burst.
	require.Equal(rate.Limit(50), p.limiter.Limit(),
		"sustained rate must equal configured RateLimit (was fixed at 1 rps)")
	require.Equal(50, p.limiter.Burst())
}
