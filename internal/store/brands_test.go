package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/config"
)

func TestSQLiteBrandVisualsRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := Open(config.Storage{Driver: "sqlite", DSN: "file:" + filepath.Join(t.TempDir(), "brands.db")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	require.NoError(t, st.Migrate(ctx))

	want := brands.Brand{
		OrgID: "org-visuals", Name: "Acme", Domains: []string{"acme.example"},
		Colors: []string{"#F14635", "#FFFFFF"}, LogoPHash: "0123456789abcdef",
	}
	require.NoError(t, st.AddBrand(ctx, want))
	got, err := st.ListBrands(ctx, want.OrgID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, want.Name, got[0].Name)
	require.Equal(t, want.Colors, got[0].Colors)
	require.Equal(t, want.LogoPHash, got[0].LogoPHash)
}
