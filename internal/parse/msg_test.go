package parse

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMSGRejectsNonOLEInput(t *testing.T) {
	_, err := New().MSG([]byte("not an Outlook message"))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotImplemented)
}

func TestMSGTextDecodesUTF16AndTrimsTerminator(t *testing.T) {
	props := map[string][]byte{"utf16": {0x41, 0x00, 0x42, 0x00, 0x00, 0x00}}
	require.Equal(t, "AB", msgText(props, "utf16", "ansi"))
	require.Equal(t, "fallback", msgText(map[string][]byte{"ansi": []byte("fallback\x00")}, "utf16", "ansi"))
}

func TestMSGDWORDIsBounded(t *testing.T) {
	require.Zero(t, msgDWORD([]byte{1, 2, 3}))
	require.Equal(t, uint32(0x04030201), msgDWORD([]byte{1, 2, 3, 4}))
}
