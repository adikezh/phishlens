package sandbox

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChromeRejectsPrivateAndUnsafeURLsBeforeConnecting(t *testing.T) {
	runner := New("http://127.0.0.1:9222", false)
	for _, raw := range []string{"http://127.0.0.1/login", "http://localhost/login", "file:///etc/passwd", "https://user:pass@example.com/"} {
		_, err := runner.Detonate(context.Background(), raw)
		require.Error(t, err, raw)
	}
}

func TestChromeDoesNotStartWithoutEndpoint(t *testing.T) {
	runner := New("", false)
	_, err := runner.Detonate(context.Background(), "https://203.0.113.7/login")
	require.ErrorContains(t, err, "endpoint is empty")
}
