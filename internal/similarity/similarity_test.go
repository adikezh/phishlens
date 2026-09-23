package similarity

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDamerauLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"kaspi", "kaspi", 0},
		{"kaspi", "kapsi", 1}, // transposition
		{"kaspi", "kaspii", 1},
		{"kaspi", "kasp", 1},
		{"kaspi", "kaspy", 1},
		{"halyk", "halyc", 1},
		{"paypal", "paypa1", 1},
		{"microsoft", "micros0ft", 1},
		{"kaspi", "halyk", 4},
		{"", "abc", 3},
		{"abc", "", 3},
		{"кaspi", "kaspi", 1}, // cyrillic к vs latin k
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, DamerauLevenshtein(tc.a, tc.b), "%q vs %q", tc.a, tc.b)
	}
}

func TestHomoglyphsAndScripts(t *testing.T) {
	table := map[rune]rune{'а': 'a', 'р': 'p', 'с': 'c', '0': 'o'}
	require.Equal(t, "kaspi.kz", NormalizeHomoglyphs("kаspi.kz", table))
	require.Equal(t, "paypal.com", NormalizeHomoglyphs("рaурal.com", map[rune]rune{'р': 'p', 'у': 'y'}))
	require.Equal(t, "google", NormalizeHomoglyphs("G00gle", table))

	require.True(t, HasMixedScript("kаspi"))  // latin + cyrillic а
	require.False(t, HasMixedScript("kaspi")) // pure latin
	require.False(t, HasMixedScript("каспи")) // pure cyrillic
	require.False(t, HasMixedScript("kaspi.kz"))
}
