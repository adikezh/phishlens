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

func TestWazuhNotifier(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	w := NewWazuh(config.Wazuh{APIURL: srv.URL, User: "api", MinVerdict: "suspicious"}, "secret")
	sub := &domain.Submission{ID: "01X", Channel: domain.ChannelAPI, Message: &domain.ParsedMail{TextBody: "private"}, Result: &domain.Analysis{
		Verdict: domain.VerdictPhishing, Score: 90, Signals: []domain.Signal{{ID: "x"}},
	}}
	require.NoError(t, w.Notify(context.Background(), sub))
	require.NotEmpty(t, gotAuth)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(gotBody, &payload))
	require.Equal(t, "phishlens", payload["integration"])
	require.NotContains(t, string(gotBody), "private")
}

func TestWazuhMinVerdict(t *testing.T) {
	w := NewWazuh(config.Wazuh{APIURL: "http://127.0.0.1:1", MinVerdict: "phishing"}, "")
	sub := &domain.Submission{Result: &domain.Analysis{Verdict: domain.VerdictClean}}
	require.NoError(t, w.Notify(context.Background(), sub))
}
