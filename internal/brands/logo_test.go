package brands

import (
	"image"
	"image/color"
	"testing"

	"github.com/corona10/goimagehash"
	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
)

func TestMatchLogoPHash(t *testing.T) {
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
	hash, err := goimagehash.PerceptionHash(img)
	require.NoError(t, err)
	m := NewMatcher([]Brand{{Name: "Acme", Domains: []string{"acme.example"}, LogoPHash: hash.ToString()}}, nil)
	match := m.Match(&domain.ParsedMail{Images: []domain.InlineImage{{PHash: hash.ToString()}}})
	require.NotNil(t, match)
	require.Equal(t, "Acme", match.Name)
	require.Equal(t, "logo", match.Method)
	require.GreaterOrEqual(t, match.Score, 0.9)
}
