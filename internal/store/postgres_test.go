package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// TestPostgresStore exercises the same persistence contract used by the
// service. CI supplies a disposable PostgreSQL service; local runs can opt in
// with PHISHLENS_POSTGRES_DSN.
func TestPostgresStore(t *testing.T) {
	dsn := os.Getenv("PHISHLENS_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PHISHLENS_POSTGRES_DSN is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Open(config.Storage{Driver: "postgres", DSN: dsn})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(ctx))

	now := time.Now().UTC().Truncate(time.Microsecond)
	orgID := "org-it-" + ulid.Make().String()
	sub := &domain.Submission{
		ID: ulid.Make().String(), OrgID: orgID, Channel: domain.ChannelAPI,
		Kind: domain.KindEML, ReceivedAt: now, Status: domain.StatusAnalyzed,
		Message: &domain.ParsedMail{
			From:    domain.Address{Addr: "fraud@example.test", Domain: "example.test"},
			Subject: "verify account", Links: []domain.Link{{Href: "https://login.example.test/", Domain: "login.example.test"}},
		},
		Result: &domain.Analysis{
			Score: 85, Verdict: domain.VerdictPhishing, Confidence: 0.97,
			AttackType: domain.AttackCredentialHarvesting, DurationMs: 12,
			Signals: []domain.Signal{{ID: "test.signal", Category: domain.CategoryLink, Weight: 30, Confidence: 1, Explanation: "test", Source: domain.SourceHeuristic}},
		},
	}
	require.NoError(t, st.SaveSubmission(ctx, sub, true))

	loaded, err := st.GetSubmission(ctx, sub.ID)
	require.NoError(t, err)
	require.Equal(t, domain.StatusAnalyzed, loaded.Status)
	require.NotNil(t, loaded.Message)
	require.Equal(t, "verify account", loaded.Message.Subject)
	require.Len(t, loaded.Result.Signals, 1)
	require.Equal(t, "verify account", loaded.Message.Subject)

	require.NoError(t, st.UpdateSubmissionStatus(ctx, sub.ID, domain.StatusConfirmedPhish, "analyst"))
	iocs, err := st.ListIOCs(ctx, orgID, now.Add(-time.Minute))
	require.NoError(t, err)
	require.Len(t, iocs, 3)

	require.NoError(t, st.AddEntry(ctx, ListEntry{OrgID: orgID, Kind: ListBlock, Value: "example.test", CreatedBy: "analyst"}))
	entries, err := st.ListEntries(ctx, orgID, ListBlock)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	key := APIKey{ID: "key-" + sub.ID, OrgID: orgID, Name: "integration", Role: "analyst", KeyHash: "hash-" + sub.ID, CreatedAt: now}
	require.NoError(t, st.CreateAPIKey(ctx, key))
	gotKey, err := st.GetAPIKeyByHash(ctx, key.KeyHash)
	require.NoError(t, err)
	require.Equal(t, key.ID, gotKey.ID)

	stats, err := st.Stats(ctx, orgID, now.Add(-time.Minute))
	require.NoError(t, err)
	require.Equal(t, 1, stats.Total)
	require.Equal(t, 1, stats.ByStatus[string(domain.StatusConfirmedPhish)])

	require.NoError(t, st.Audit(ctx, AuditEntry{OrgID: orgID, Actor: "analyst", Action: "integration.test", Target: sub.ID}))
	require.NoError(t, st.DeleteSubmission(ctx, sub.ID))
	_, err = st.GetSubmission(ctx, sub.ID)
	require.ErrorIs(t, err, ErrNotFound)
}
