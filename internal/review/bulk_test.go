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

func TestBulkStatusAppliesAndAuditsWithinOrganization(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(config.Storage{Driver: "sqlite", DSN: "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "bulk.db"))})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(ctx))
	for _, id := range []string{"a", "b"} {
		require.NoError(t, st.SaveSubmission(ctx, &domain.Submission{ID: id, OrgID: "org-a", Channel: domain.ChannelAPI, Kind: domain.KindText, ReceivedAt: time.Now().UTC(), Status: domain.StatusInReview}, false))
	}
	q := NewQueue(st)
	applied, err := q.BulkStatus(ctx, []string{"a", "b"}, domain.StatusConfirmedPhish, "analyst", "org-a")
	require.NoError(t, err)
	require.Equal(t, 2, applied)
	for _, id := range []string{"a", "b"} {
		sub, getErr := st.GetSubmission(ctx, id)
		require.NoError(t, getErr)
		require.Equal(t, domain.StatusConfirmedPhish, sub.Status)
	}
	_, err = q.BulkStatus(ctx, []string{"a"}, domain.StatusConfirmedClean, "analyst", "org-b")
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestBulkStatusBoundsInput(t *testing.T) {
	st, err := store.Open(config.Storage{Driver: "sqlite", DSN: "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "bulk-bounds.db"))})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(context.Background()))
	_, err = NewQueue(st).BulkStatus(context.Background(), nil, domain.StatusConfirmedClean, "analyst", "")
	require.Error(t, err)
}
