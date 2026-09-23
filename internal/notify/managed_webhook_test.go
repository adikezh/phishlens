package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/crypto"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/store"
)

func TestManagedWebhookDelivery(t *testing.T) {
	const secret = "managed-webhook-secret-012345"
	var gotBody []byte
	var gotTimestamp string
	var gotSignature string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTimestamp = r.Header.Get("X-PhishLens-Timestamp")
		gotSignature = r.Header.Get("X-PhishLens-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	st, err := store.Open(config.Storage{Driver: "sqlite", DSN: "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "managed.db"))})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(context.Background()))
	cipher, err := crypto.New([]byte(strings.Repeat("a", 32)))
	require.NoError(t, err)
	sqlite := st.(*store.SQLite)
	sqlite.SetCipher(cipher)
	require.NoError(t, st.CreateWebhook(context.Background(), store.Webhook{
		ID: "managed-1", OrgID: "org-managed", Name: "test", URL: srv.URL,
		Secret: secret, Enabled: true, CreatedAt: time.Now().UTC(),
	}))

	f := NewFanout(config.Integrations{}, zerolog.Nop())
	f.SetWebhookStore(st)
	sub := &domain.Submission{ID: "submission-managed", OrgID: "org-managed", Channel: domain.ChannelAPI, ReceivedAt: time.Now().UTC(), Result: &domain.Analysis{Verdict: domain.VerdictPhishing, Score: 90}}
	f.Notify(context.Background(), sub)

	require.NotEmpty(t, gotBody)
	require.NotEmpty(t, gotTimestamp)
	require.Equal(t, Sign([]byte(secret), gotTimestamp, gotBody), gotSignature)
	require.Contains(t, string(gotBody), "phishlens.analysis")
	require.NotContains(t, string(gotBody), secret)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(gotTimestamp + "."))
	mac.Write(gotBody)
	require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), gotSignature)
}
