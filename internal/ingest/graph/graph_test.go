package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/stretchr/testify/require"
)

func TestFetchMIMEEnforcesBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxMessageBytes+1))
	}))
	defer server.Close()
	r := New(config.Graph{Mailbox: "phish@example.test"})
	r.baseURL = server.URL
	_, err := r.fetchMIME(context.Background(), server.Client(), "message-1")
	require.ErrorContains(t, err, "exceeds 25 MiB")
}

func TestSaveStateIsPrivateAndReloadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "delta.token")
	require.NoError(t, saveState(path, "https://graph.example/delta?token=abc"))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "https://graph.example/delta?token=abc\n", string(b))
	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}
