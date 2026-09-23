package link

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var (
	reLongB64 = regexp.MustCompile(`[A-Za-z0-9+/_\-]{40,}={0,2}`)
	reLongHex = regexp.MustCompile(`(?i)(?:%[0-9a-f]{2}){8,}|[0-9a-f]{32,}`)
)

// L-04: "@" in URL (userinfo trick), data:/javascript: URIs, long base64/hex segments.
func obfuscated(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	for _, l := range in.Mail.Links {
		reason := ""
		lower := strings.ToLower(l.Href)
		switch {
		case strings.HasPrefix(lower, "data:"):
			reason = "data: URI"
		case strings.HasPrefix(lower, "javascript:"):
			reason = "javascript: URI"
		default:
			if u, err := url.Parse(l.Href); err == nil && u.User != nil {
				reason = "@ userinfo in URL"
			} else if reLongB64.MatchString(l.Href) || reLongHex.MatchString(l.Href) {
				reason = "long encoded segment"
			}
		}
		if reason == "" {
			continue
		}
		out = append(out, signals.New(IDObfuscated, domain.CategoryLink, 15, 0.8, l.Href, in.Lang, reason))
		if len(out) >= 3 {
			break
		}
	}
	return out, nil
}
