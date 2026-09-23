package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealOpen(t *testing.T) {
	keyHex, err := GenerateKey()
	require.NoError(t, err)
	key, _ := hex.DecodeString(keyHex)
	c, err := New(key)
	require.NoError(t, err)

	msg := []byte(`{"subject":"Срочно","text_body":"..."}`)
	sealed, err := c.Seal(msg)
	require.NoError(t, err)
	require.NotEqual(t, msg, sealed)

	opened, err := c.Open(sealed)
	require.NoError(t, err)
	require.Equal(t, msg, opened)

	sealed[len(sealed)-1] ^= 0xFF
	_, err = c.Open(sealed)
	require.Error(t, err, "tampering detected")

	_, err = New([]byte("short"))
	require.Error(t, err)
}

func TestFromEnv(t *testing.T) {
	t.Setenv("PL_TEST_KEY", "")
	c, err := FromEnv("PL_TEST_KEY")
	require.NoError(t, err)
	require.Nil(t, c, "unset key → no cipher")

	k, _ := GenerateKey()
	t.Setenv("PL_TEST_KEY", k)
	c, err = FromEnv("PL_TEST_KEY")
	require.NoError(t, err)
	require.NotNil(t, c)
}
