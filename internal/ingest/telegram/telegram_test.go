package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestHandleUpdateBindsOrganisationAndAnalyzesText(t *testing.T) {
	var sent []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if text, ok := body["text"].(string); ok {
			sent = append(sent, text)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer api.Close()
	var got app.Request
	r := New(config.Telegram{}, func(_ context.Context, req app.Request) (*domain.Submission, error) {
		got = req
		return &domain.Submission{Result: &domain.Analysis{Verdict: domain.VerdictPhishing, Score: 92, Signals: []domain.Signal{{Explanation: "опасная ссылка"}}}}, nil
	})
	r.apiBase = api.URL
	require.NoError(t, r.handleUpdate(context.Background(), "token", update{ID: 1, Message: &message{Chat: chat{ID: 7}, Text: "/start org-demo"}}))
	require.NoError(t, r.handleUpdate(context.Background(), "token", update{ID: 2, Message: &message{Chat: chat{ID: 7}, Text: "Проверьте https://example.test"}}))
	require.Equal(t, "org-demo", got.OrgID)
	require.Equal(t, domain.ChannelTelegram, got.Channel)
	require.Equal(t, domain.KindText, got.Kind)
	require.Equal(t, "Проверьте https://example.test", string(got.Data))
	require.Len(t, sent, 2)
	require.True(t, strings.Contains(sent[1], "phishing"))
}

func TestUnboundChatIsRejectedWithoutAnalyzer(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer api.Close()
	called := false
	r := New(config.Telegram{}, func(context.Context, app.Request) (*domain.Submission, error) {
		called = true
		return nil, nil
	})
	r.apiBase = api.URL
	require.NoError(t, r.handleUpdate(context.Background(), "token", update{Message: &message{Chat: chat{ID: 9}, Text: "hello"}}))
	require.False(t, called)
}
