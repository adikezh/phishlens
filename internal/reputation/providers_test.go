package reputation

import (
	"strings"
	"testing"
	"time"
)

func TestParseRDAPAge(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	age, err := parseRDAPAge([]byte(`{"events":[{"eventAction":"last changed","eventDate":"2026-09-20T00:00:00Z"},{"eventAction":"registration","eventDate":"2026-09-01T00:00:00Z"}]}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if age != 22*24*time.Hour+12*time.Hour {
		t.Fatalf("age=%s", age)
	}
}

func TestOpenPhishFeedContains(t *testing.T) {
	feed := "https://example.com/login\nhttps://sub.example.net/a\nnot a url\n"
	for _, tc := range []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.net", true},
		{"example.net", false},
	} {
		got, err := openPhishFeedContains(strings.NewReader(feed), tc.domain)
		if err != nil || got != tc.want {
			t.Fatalf("domain=%q got=%v err=%v want=%v", tc.domain, got, err, tc.want)
		}
	}
}

func TestParseURLhausResponse(t *testing.T) {
	listed, err := parseURLhausResponse([]byte(`{"query_status":"ok","urls":[{"url":"https://bad.example/"}]}`))
	if err != nil || !listed {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	listed, err = parseURLhausResponse([]byte(`{"query_status":"no_results","urls":[]}`))
	if err != nil || listed {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
}

func TestURLhausRequiresAuthKey(t *testing.T) {
	listed, err := urlhausLookup(t.Context(), "example.com", "")
	if err == nil || listed {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
}
