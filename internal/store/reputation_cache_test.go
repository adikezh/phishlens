package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
)

func TestSQLiteReputationCacheTTL(t *testing.T) {
	ctx := context.Background()
	st, err := Open(config.Storage{
		Driver: "sqlite",
		DSN:    "file:reputation-cache-test?mode=memory&cache=shared",
	})
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.Migrate(ctx))

	wantExpiry := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	require.NoError(t, st.PutReputationCache(ctx, "rdap:example.com", `{"age_days":42}`, wantExpiry))

	got, err := st.GetReputationCache(ctx, "rdap:example.com")
	require.NoError(t, err)
	require.Equal(t, "rdap:example.com", got.Key)
	require.Equal(t, `{"age_days":42}`, got.Value)
	require.WithinDuration(t, wantExpiry, got.ExpiresAt, time.Microsecond)

	require.NoError(t, st.PutReputationCache(ctx, "rdap:expired.example", "0", time.Now().Add(-time.Second)))
	_, err = st.GetReputationCache(ctx, "rdap:expired.example")
	require.ErrorIs(t, err, ErrNotFound)
}
