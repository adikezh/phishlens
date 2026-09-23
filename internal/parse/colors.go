package parse

import (
	"fmt"
	"image"
	"sort"
)

const maxColorSamples = 100_000

type colorCount struct {
	value uint32
	count int
}

// dominantColors returns up to three quantized opaque colors in descending
// frequency order. Sampling is capped so a large but valid image cannot turn
// this inexpensive metadata feature into an unbounded CPU loop.
func dominantColors(img image.Image) []string {
	if img == nil {
		return nil
	}
	b := img.Bounds()
	width, height := b.Dx(), b.Dy()
	if width <= 0 || height <= 0 {
		return nil
	}
	step := 1
	if pixels := width * height; pixels > maxColorSamples {
		step = pixels/maxColorSamples + 1
	}
	counts := make(map[uint32]int)
	for y := b.Min.Y; y < b.Max.Y; y += step {
		for x := b.Min.X; x < b.Max.X; x += step {
			r, g, bl, a := img.At(x, y).RGBA()
			if a < 0x8000 {
				continue
			}
			// Quantize each channel to 16 levels. This tolerates JPEG noise and
			// minor rendering differences while preserving brand palettes.
			qr, qg, qb := uint32(r>>12)*17, uint32(g>>12)*17, uint32(bl>>12)*17
			counts[qr<<16|qg<<8|qb]++
		}
	}
	items := make([]colorCount, 0, len(counts))
	for value, count := range counts {
		items = append(items, colorCount{value: value, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].value < items[j].value
	})
	if len(items) > 3 {
		items = items[:3]
	}
	colors := make([]string, 0, len(items))
	for _, item := range items {
		colors = append(colors, fmt.Sprintf("#%06X", item.value))
	}
	return colors
}
