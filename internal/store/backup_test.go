package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

func TestSQLiteBackupAndRestore(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "phishlens.db")
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	st, err := Open(config.Storage{Driver: "sqlite", DSN: "file:" + dbPath})
	require.NoError(t, err)
	require.NoError(t, st.Migrate(ctx))
	sub := &domain.Submission{ID: "01JBACKUP0000000000000000", Channel: domain.ChannelAPI, Kind: domain.KindText, ReceivedAt: time.Now().UTC(), Status: domain.StatusAnalyzed}
	require.NoError(t, st.SaveSubmission(ctx, sub, false))
	require.NoError(t, st.Close())
	require.NoError(t, BackupSQLite(ctx, "file:"+dbPath, backupPath))
	require.NoError(t, RestoreSQLite(ctx, "file:"+dbPath, backupPath, true))
	restored, err := Open(config.Storage{Driver: "sqlite", DSN: "file:" + dbPath})
	require.NoError(t, err)
	defer restored.Close()
	got, err := restored.GetSubmission(ctx, sub.ID)
	require.NoError(t, err)
	require.Equal(t, sub.ID, got.ID)
}
