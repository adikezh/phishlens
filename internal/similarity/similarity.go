// Package similarity implements string-distance helpers used for brand lookalike
// detection (D-04): optimal-string-alignment Damerau–Levenshtein, homoglyph
// normalisation and mixed-script detection.
package similarity

import (
	"strings"
	"unicode"
)

// DamerauLevenshtein returns the OSA (restricted) Damerau–Levenshtein distance
// between a and b, counting insert, delete, substitute and adjacent transposition.
func DamerauLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[la][lb]
}

// NormalizeHomoglyphs lowercases s and maps confusable runes to their Latin
// equivalents using table (data/homoglyphs.yaml).
func NormalizeHomoglyphs(s string, table map[rune]rune) string {
	if len(table) == 0 {
		return strings.ToLower(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if m, ok := table[r]; ok {
			b.WriteRune(m)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Scripts reports which scripts appear in s.
func Scripts(s string) (latin, cyrillic, other bool) {
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r):
		case unicode.Is(unicode.Latin, r):
			latin = true
		case unicode.Is(unicode.Cyrillic, r):
			cyrillic = true
		default:
			other = true
		}
	}
	return
}

// HasMixedScript is true when Latin letters are mixed with Cyrillic (or another
// script) inside one string — the classic IDN homograph trick (D-03).
func HasMixedScript(s string) bool {
	latin, cyr, other := Scripts(s)
	return latin && (cyr || other)
}

// ContainsToken reports whether token equals any label of the host split on '.', '-', '_'.
func ContainsToken(labels []string, token string) bool {
	for _, l := range labels {
		if l == token {
			return true
		}
	}
	return false
}
