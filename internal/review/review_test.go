package review

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/store"
)

func TestQueueActionsPersistDecisionAndAudit(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(config.Storage{Driver: "sqlite", DSN: "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "review.db"))})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(ctx))
	sub := &domain.Submission{
		ID: "review-submission", OrgID: "org-review", Channel: domain.ChannelAPI,
		Kind: domain.KindText, ReceivedAt: time.Now().UTC(), Status: domain.StatusAnalyzed,
		Message: &domain.ParsedMail{From: domain.Address{Domain: "sender.example"}},
		Result:  &domain.Analysis{Verdict: domain.VerdictSuspicious},
	}
	require.NoError(t, st.SaveSubmission(ctx, sub, false))

	q := NewQueue(st)
	require.NoError(t, q.BlockDomain(ctx, sub.ID, "sender.example", "analyst"))
	entries, err := st.ListEntries(ctx, "org-review", store.ListBlock)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	require.NoError(t, q.CreateIncident(ctx, sub.ID, "analyst"))
	got, err := st.GetSubmission(ctx, sub.ID)
	require.NoError(t, err)
	require.Equal(t, domain.StatusEscalated, got.Status)
}

func TestBlockDomainRejectsIPAndMalformedValue(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(config.Storage{Driver: "sqlite", DSN: "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "review.db"))})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(ctx))
	sub := &domain.Submission{ID: "review-invalid", OrgID: "org-review", Channel: domain.ChannelAPI, Kind: domain.KindText, ReceivedAt: time.Now().UTC(), Status: domain.StatusAnalyzed, Message: &domain.ParsedMail{}}
	require.NoError(t, st.SaveSubmission(ctx, sub, false))
	q := NewQueue(st)
	require.Error(t, q.BlockDomain(ctx, sub.ID, "127.0.0.1", "analyst"))
	require.Error(t, q.BlockDomain(ctx, sub.ID, "not/a-domain", "analyst"))
}
