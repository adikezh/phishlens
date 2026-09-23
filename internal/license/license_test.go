package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func signedKey(t *testing.T, private ed25519.PrivateKey, c claims) string {
	t.Helper()
	b, err := json.Marshal(c)
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(b) + "." + enc.EncodeToString(ed25519.Sign(private, b))
}

func TestLoadVerifiesSignedBusinessLicense(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	t.Setenv("PL_LICENSE_PUBLIC_KEY", base64.RawURLEncoding.EncodeToString(pub))
	t.Setenv("PL_LICENSE_KEY", signedKey(t, private, claims{
		Edition: Business, Org: "org-a", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Features: map[string]bool{FeatureIMAP: true},
	}))
	l := Load()
	require.Equal(t, Business, l.Edition)
	require.Equal(t, "org-a", l.Org)
	require.True(t, l.Has(FeatureIMAP))
	require.False(t, l.Has(FeatureGraph))
}

func TestLoadRejectsTamperedAndExpiredLicense(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	t.Setenv("PL_LICENSE_PUBLIC_KEY", base64.RawURLEncoding.EncodeToString(pub))
	key := signedKey(t, private, claims{Edition: Business, Org: "org-a", ExpiresAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), Features: map[string]bool{FeatureIMAP: true}})
	t.Setenv("PL_LICENSE_KEY", key)
	require.Equal(t, Community, Load().Edition)
	t.Setenv("PL_LICENSE_KEY", strings.Replace(key, "a", "b", 1))
	require.Equal(t, Community, Load().Edition)
}
