package i18n

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalogs(t *testing.T) {
	require.NoError(t, Err())
	require.Equal(t, "Фишинг", T("ru", "verdict.phishing"))
	require.Equal(t, "Phishing", T("en", "verdict.phishing"))
	require.Equal(t, "Фишинг", T("kz", "verdict.phishing"))
	require.Contains(t, T("ru", "header.replyto_mismatch", "evil.com", "kaspi.kz"), "evil.com")
	require.Contains(t, T("en", "header.replyto_mismatch", "evil.com", "kaspi.kz"), "kaspi.kz")
	require.Equal(t, "unknown.key", T("ru", "unknown.key"), "missing key falls back to the key")
	require.Equal(t, "ru", Normalize("RU-kz"))
	require.Equal(t, "kz", Normalize("kk"))
	require.Equal(t, "ru", Normalize("de"))
}

// Every ru key must exist in en and kz, and placeholder counts must match.
func TestCatalogParity(t *testing.T) {
	once.Do(load)
	ru := catalogs["ru"]
	for _, lang := range []string{"en", "kz"} {
		for key, ruTmpl := range ru {
			other, ok := catalogs[lang][key]
			require.True(t, ok, "%s missing key %s", lang, key)
			require.Equal(t, countVerbs(ruTmpl), countVerbs(other), "%s/%s placeholder mismatch", lang, key)
		}
	}
}

func countVerbs(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '%' && s[i+1] != '%' {
			n++
		}
	}
	return n
}
