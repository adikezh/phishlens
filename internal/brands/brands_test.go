package brands

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/data"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/refdata"
)

func matcher(t *testing.T) *Matcher {
	t.Helper()
	f, err := data.FS.Open("brands.yaml")
	require.NoError(t, err)
	defer f.Close()
	list, err := Load(f)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(list), 100)
	rd, err := refdata.Load(data.FS, "")
	require.NoError(t, err)
	return NewMatcher(list, rd.Homoglyphs)
}

// D-04 table: lookalike vs official vs unrelated.
func TestMatchDomain(t *testing.T) {
	m := matcher(t)
	cases := []struct {
		host         string
		wantBrand    string
		wantOfficial bool
	}{
		// official
		{"kaspi.kz", "Kaspi", true},
		{"mail.kaspi.kz", "Kaspi", true},
		{"notify.kaspi.kz", "Kaspi", true},
		{"halykbank.kz", "Halyk Bank", true},
		{"egov.kz", "eGov", true},
		{"microsoft.com", "Microsoft", true},
		// typosquat / brand token on a foreign domain
		{"kaspi-secure-login.com", "Kaspi", false},
		{"kaspi.bank-verify.top", "Kaspi", false},
		{"halyk.secure-login.ru", "Halyk Bank", false},
		{"egov-kz.site", "eGov", false},
		{"login-kaspi.xyz", "Kaspi", false},
		{"beeline-bonus.click", "Beeline Kazakhstan", false},
		// Damerau-Levenshtein ≤ 2
		{"kaspii.kz", "Kaspi", false},
		{"halykbnak.kz", "Halyk Bank", false},
		{"paypa1.com", "PayPal", false},
		{"micros0ft.com", "Microsoft", false},
		// homoglyphs (cyrillic а/р/с)
		{"kаspi.kz", "Kaspi", false},
		{"раypal.com", "PayPal", false},
		// unrelated
		{"company.kz", "", false},
		{"gmail.com", "", false},
		{"example.com", "", false},
		{"news.ycombinator.com", "", false},
		{"bank.kz", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			name, official, method, score := m.MatchDomain(tc.host)
			require.Equal(t, tc.wantBrand, name, "method=%s score=%.2f", method, score)
			require.Equal(t, tc.wantOfficial, official)
			if name != "" {
				require.Greater(t, score, 0.0)
			}
		})
	}
}

func TestMatchTextAndMail(t *testing.T) {
	m := matcher(t)
	name, score := m.MatchText("Ваш аккаунт Kaspi Gold заблокирован", "подтвердите данные в Kaspi.kz")
	require.Equal(t, "Kaspi", name)
	require.Greater(t, score, 0.5)

	name, _ = m.MatchText("Weekly digest", "nothing branded here")
	require.Equal(t, "", name)

	mail := &domain.ParsedMail{
		From:    parse.ParseAddress(`"Kaspi" <security@kaspi-secure.top>`),
		Subject: "Срочно",
		Links:   []domain.Link{{Href: "http://kaspi-secure.top/x", Domain: "kaspi-secure.top"}},
	}
	bm := m.Match(mail)
	require.NotNil(t, bm)
	require.Equal(t, "Kaspi", bm.Name)
	require.False(t, bm.Official)
	require.True(t, strings.HasPrefix(bm.Method, "typosquat") || bm.Method == "domain_similarity", bm.Method)

	mail = &domain.ParsedMail{From: parse.ParseAddress("noreply@halykbank.kz")}
	bm = m.Match(mail)
	require.NotNil(t, bm)
	require.True(t, bm.Official)
	require.Equal(t, "domain", bm.Method)
}

func TestCustomBrand(t *testing.T) {
	m := matcher(t)
	m.Add(Brand{Name: "Acme KZ", Domains: []string{"acme.kz"}, Keywords: []string{"acme"}, OrgID: "org1"})
	name, official, _, _ := m.MatchDomain("acme.kz")
	require.Equal(t, "Acme KZ", name)
	require.True(t, official)
	name, official, _, _ = m.MatchDomain("acme-portal.com")
	require.Equal(t, "Acme KZ", name)
	require.False(t, official)
}
