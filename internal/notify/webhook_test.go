package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
)

func TestWebhookSignature(t *testing.T) {
	secret := "s3cret"
	var gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-PhishLens-Signature")
		gotTS = r.Header.Get("X-PhishLens-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sub := &domain.Submission{ID: "01X", Channel: domain.ChannelAPI,
		Message: &domain.ParsedMail{From: domain.Address{Addr: "a@evil.com", Domain: "evil.com"}, Links: []domain.Link{{Href: "http://x.top", Domain: "x.top"}}, TextBody: "secret body"},
		Result:  &domain.Analysis{Score: 90, Verdict: domain.VerdictPhishing, AttackType: domain.AttackCredentialHarvesting, Signals: []domain.Signal{{ID: "x"}}}}
	require.NoError(t, NewWebhook(srv.URL, secret).Notify(context.Background(), sub))
	require.Equal(t, Sign([]byte(secret), gotTS, gotBody), gotSig)

	var ev Event
	require.NoError(t, json.Unmarshal(gotBody, &ev))
	require.Equal(t, "evil.com", ev.SenderDomain)
	require.Equal(t, []string{"x.top"}, ev.LinkDomains)
	require.NotContains(t, string(gotBody), "secret body", "bodies never leave the service")
}
