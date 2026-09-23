package parse

import (
	"bytes"
	"image/png"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/stretchr/testify/require"
)

func TestDecodeQRHTTPURL(t *testing.T) {
	matrix, err := qrcode.NewQRCodeWriter().EncodeWithoutHint("https://login.example.test/verify", gozxing.BarcodeFormat_QR_CODE, 160, 160)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, matrix))

	got, err := New().Image(nil, buf.Bytes())
	require.ErrorIs(t, err, ErrOCRUnavailable)
	require.NotNil(t, got)
	require.Len(t, got.Links, 1)
	require.Equal(t, "https://login.example.test/verify", got.Links[0].Href)
}
