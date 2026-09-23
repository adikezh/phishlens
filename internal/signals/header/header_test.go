package header

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/signals"
)

func input(m *domain.ParsedMail) *signals.Input {
	return &signals.Input{Mail: m, Lang: "ru"}
}

func TestReplyToMismatch(t *testing.T) {
	cases := []struct {
		name          string
		from, replyTo string
		want          bool
	}{
		{"different domain", "a@kaspi.kz", "b@evil.com", true},
		{"lookalike domain", "a@kaspi.kz", "b@kaspi-secure.com", true},
		{"free mail reply", "ceo@company.kz", "ceo@gmail.com", true},
		{"same domain", "a@kaspi.kz", "b@kaspi.kz", false},
		{"subdomain", "a@kaspi.kz", "b@mail.kaspi.kz", false},
		{"no reply-to", "a@kaspi.kz", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &domain.ParsedMail{From: parse.ParseAddress(tc.from), ReplyTo: parse.ParseAddress(tc.replyTo)}
			sigs, err := replyToMismatch(context.Background(), input(m))
			require.NoError(t, err)
			require.Equal(t, tc.want, len(sigs) == 1, "signals: %+v", sigs)
			if tc.want {
				require.Equal(t, IDReplyToMismatch, sigs[0].ID)
				require.NotEmpty(t, sigs[0].Explanation)
			}
		})
	}
}

func TestReplyToMismatchAllowsBrandESP(t *testing.T) {
	m := &domain.ParsedMail{From: parse.ParseAddress("alerts@kaspi.kz"), ReplyTo: parse.ParseAddress("reply@mail.kaspi.kz")}
	in := input(m)
	in.Brand = &domain.BrandMatch{Name: "Kaspi", Official: true}
	in.Brands = brands.NewMatcher([]brands.Brand{{Name: "Kaspi", Domains: []string{"kaspi.kz"}, ESPDomains: []string{"mail.kaspi.kz"}}}, nil)
	sigs, err := replyToMismatch(context.Background(), in)
	require.NoError(t, err)
	require.Empty(t, sigs)
}

func TestDisplayNameEmail(t *testing.T) {
	cases := []struct {
		from string
		want bool
	}{
		{`"ceo@company.kz" <attacker@gmail.com>`, true},
		{`"Support support@kaspi.kz" <x@evil.top>`, true},
		{`"a.b@bank.kz via Docs" <no-reply@mailer.io>`, true},
		{`"Kaspi Bank" <security@kaspi.kz>`, false},
		{`"user@company.kz" <user@company.kz>`, false},
		{`security@kaspi.kz`, false},
	}
	for _, tc := range cases {
		t.Run(tc.from, func(t *testing.T) {
			m := &domain.ParsedMail{From: parse.ParseAddress(tc.from)}
			sigs, err := displayNameEmail(context.Background(), input(m))
			require.NoError(t, err)
			require.Equal(t, tc.want, len(sigs) == 1)
		})
	}
}

func TestReturnPathMismatch(t *testing.T) {
	cases := []struct {
		from, rp string
		want     bool
	}{
		{"a@kaspi.kz", "bounce@evil.com", true},
		{"a@kaspi.kz", "b@kaspi-secure-login.com", true},
		{"a@company.kz", "x@sendgrid.net", true},
		{"a@kaspi.kz", "bounce@kaspi.kz", false},
		{"a@kaspi.kz", "bounce@mta.kaspi.kz", false},
		{"a@kaspi.kz", "", false},
	}
	for _, tc := range cases {
		m := &domain.ParsedMail{From: parse.ParseAddress(tc.from), ReturnPath: parse.ParseAddress(tc.rp)}
		sigs, err := returnPathMismatch(context.Background(), input(m))
		require.NoError(t, err)
		require.Equal(t, tc.want, len(sigs) == 1, "%s / %s", tc.from, tc.rp)
	}
}

func TestMessageID(t *testing.T) {
	mk := func(from, mid string) *domain.ParsedMail {
		m := &domain.ParsedMail{From: parse.ParseAddress(from), Headers: map[string][]string{"Subject": {"x"}}}
		if mid != "" {
			m.Headers["Message-Id"] = []string{mid}
		}
		return m
	}
	cases := []struct {
		from, mid string
		wantID    string
	}{
		{"a@kaspi.kz", "<1@evil.com>", IDMessageIDMismatch},
		{"a@kaspi.kz", "<1@kaspi-login.top>", IDMessageIDMismatch},
		{"a@kaspi.kz", "", IDMessageIDMissing},
		{"a@kaspi.kz", "<1@kaspi.kz>", ""},
		{"a@kaspi.kz", "<1@mx3.kaspi.kz>", ""},
		{"a@gmail.com", "<CAF@mail.gmail.com>", ""},
	}
	for _, tc := range cases {
		sigs, err := messageID(context.Background(), input(mk(tc.from, tc.mid)))
		require.NoError(t, err)
		if tc.wantID == "" {
			require.Empty(t, sigs, "%s %s", tc.from, tc.mid)
		} else {
			require.Len(t, sigs, 1)
			require.Equal(t, tc.wantID, sigs[0].ID)
		}
	}
}

func TestDateSkew(t *testing.T) {
	recv := time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		date time.Time
		want bool
	}{
		{recv.Add(48 * time.Hour), true},
		{recv.Add(-72 * time.Hour), true},
		{recv.Add(25 * time.Hour), true},
		{recv.Add(3 * time.Hour), false},
		{recv.Add(-23 * time.Hour), false},
		{recv, false},
	}
	for _, tc := range cases {
		m := &domain.ParsedMail{Date: tc.date, Received: []domain.ReceivedHop{{Timestamp: recv}}}
		sigs, err := dateSkew(context.Background(), input(m))
		require.NoError(t, err)
		require.Equal(t, tc.want, len(sigs) == 1, "date %v", tc.date)
	}
}
