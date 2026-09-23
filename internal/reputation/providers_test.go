package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeBrowsingLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "test-key", r.URL.Query().Get("key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches":[{"threatType":"SOCIAL_ENGINEERING"}]}`))
	}))
	defer server.Close()
	listed, err := safeBrowsingLookup(context.Background(), server.Client(), server.URL, "example.test", "test-key")
	require.NoError(t, err)
	require.True(t, listed)
}

func TestAbuseIPDBLookupThreshold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "test-key", r.Header.Get("Key"))
		require.Equal(t, "203.0.113.7", r.URL.Query().Get("ipAddress"))
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":50}}`))
	}))
	defer server.Close()
	listed, err := abuseIPDBLookup(context.Background(), server.Client(), server.URL, "203.0.113.7", "test-key")
	require.NoError(t, err)
	require.True(t, listed)
}

func TestVirusTotalLookupUsesHashOnly(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/"+hash, r.URL.Path)
		require.Equal(t, "test-key", r.Header.Get("x-apikey"))
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0}}}}`))
	}))
	defer server.Close()
	listed, err := virusTotalLookup(context.Background(), server.Client(), server.URL, hash, "test-key")
	require.NoError(t, err)
	require.True(t, listed)
	require.False(t, isSHA256("not-a-hash"))
}
