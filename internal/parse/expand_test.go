package parse

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicURLRejectsSSRFTargets(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/a", "http://localhost/a", "http://169.254.169.254/latest"} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		require.Error(t, publicURL(u), raw)
	}
}

func TestNormalizeHTTPURL(t *testing.T) {
	u, err := normalizeHTTPURL("bit.ly/example")
	require.NoError(t, err)
	require.Equal(t, "https://bit.ly/example", u.String())
	_, err = normalizeHTTPURL("javascript:alert(1)")
	require.Error(t, err)
}
