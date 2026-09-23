package parse

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImageAddsPerceptualHash(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			if x < 16 {
				img.Set(x, y, color.Black)
			} else {
				img.Set(x, y, color.White)
			}
		}
	}
	var data bytes.Buffer
	require.NoError(t, png.Encode(&data, img))
	p := New()
	p.Limits.MaxImagePixels = 10000
	mail, err := p.Image(context.Background(), data.Bytes())
	require.ErrorIs(t, err, ErrOCRUnavailable)
	require.Len(t, mail.Images, 1)
	require.NotEmpty(t, mail.Images[0].PHash)
}
