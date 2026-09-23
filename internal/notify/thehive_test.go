package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

func TestTheHiveCreatesPrivacySafeAlert(t *testing.T) {
	var got theHiveAlert
	var gotOrg, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Organisation")
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &got))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	sub := &domain.Submission{
		ID: "01X", Channel: domain.ChannelAPI,
		Message: &domain.ParsedMail{
			From:        domain.Address{Addr: "a@evil.com", Domain: "evil.com"},
			Links:       []domain.Link{{Href: "https://login.evil.test", Domain: "evil.test"}},
			TextBody:    "private body must not leave PhishLens",
			Attachments: []domain.Attachment{{SHA256: "abc123"}},
		},
		Result: &domain.Analysis{Score: 90, Confidence: 0.9, Verdict: domain.VerdictPhishing, Signals: []domain.Signal{{ID: "link.punycode"}}},
	}
	cfg := config.TheHive{APIURL: srv.URL, Organisation: "org-a", MinVerdict: "suspicious"}
	require.NoError(t, NewTheHive(cfg, "secret-api-key").Notify(context.Background(), sub))
	require.Equal(t, "Bearer secret-api-key", gotAuth)
	require.Equal(t, "org-a", gotOrg)
	require.Equal(t, "01X", got.SourceRef)
	require.Equal(t, 3, got.Severity)
	require.Len(t, got.Observables, 3)
	require.NotContains(t, got.Description, "private body")
}

func TestTheHiveSkipsBelowThresholdAndReportsRemoteErrors(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad api key"))
	}))
	defer srv.Close()

	clean := &domain.Submission{ID: "clean", Result: &domain.Analysis{Verdict: domain.VerdictClean}}
	cfg := config.TheHive{APIURL: srv.URL, MinVerdict: "suspicious"}
	require.NoError(t, NewTheHive(cfg, "key").Notify(context.Background(), clean))
	require.False(t, called)

	phish := &domain.Submission{ID: "phish", Result: &domain.Analysis{Verdict: domain.VerdictPhishing}}
	err := NewTheHive(cfg, "key").Notify(context.Background(), phish)
	require.Error(t, err)
	require.Contains(t, err.Error(), "status 401")
	require.NotContains(t, err.Error(), "bad api key")
}
