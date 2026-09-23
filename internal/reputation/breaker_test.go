package reputation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCircuitBreakerOpensAndRecovers(t *testing.T) {
	now := time.Now()
	b := newCircuitBreaker(2, time.Second)
	require.True(t, b.allow(now))
	b.observe(now, errCircuitOpen)
	b.observe(now, errCircuitOpen)
	require.False(t, b.allow(now.Add(500*time.Millisecond)))
	require.True(t, b.allow(now.Add(2*time.Second)))
	b.observe(now.Add(2*time.Second), nil)
	failures, opened := b.state(now.Add(2 * time.Second))
	require.Zero(t, failures)
	require.False(t, opened)
}
