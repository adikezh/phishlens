package parse

import (
	"net"
	"net/url"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
)

// classifyLinks fills Domain/IsIP/Port/Punycode/IsShortener/Mismatch and
// de-duplicates by href. mailto:, tel: and fragment-only links are dropped;
// javascript: and data: URIs are kept (they are signals in themselves).
func (p *Parser) classifyLinks(in []domain.Link) []domain.Link {
	seen := map[string]bool{}
	out := make([]domain.Link, 0, len(in))
	for _, l := range in {
		if len(out) >= p.Limits.MaxLinks {
			break
		}
		href := strings.TrimSpace(l.Href)
		lower := strings.ToLower(href)
		if href == "" || strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "tel:") ||
			strings.HasPrefix(href, "#") || strings.HasPrefix(lower, "cid:") {
			continue
		}
		if seen[href] {
			continue
		}
		seen[href] = true
		out = append(out, p.classifyLink(href, l.Text))
	}
	return out
}

func (p *Parser) classifyLink(href, text string) domain.Link {
	l := domain.Link{Href: href, Text: text}
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "javascript:") {
		return l
	}
	raw := href
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return l
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	l.Domain = host
	l.Port = u.Port()
	l.IsIP = net.ParseIP(host) != nil
	l.Punycode = strings.Contains(host, "xn--")
	if p.Shorteners != nil {
		if _, ok := p.Shorteners[host]; ok {
			l.IsShortener = true
		} else if _, ok := p.Shorteners[netutil.RegistrableDomain(host)]; ok {
			l.IsShortener = true
		}
	}
	if th := HostFromText(text); th != "" && !l.IsIP {
		l.Mismatch = !netutil.SameRegistrable(th, host)
	} else if th != "" && l.IsIP {
		l.Mismatch = th != host
	}
	return l
}

// HostFromText returns the host when the anchor text itself looks like a URL or
// domain ("https://kaspi.kz/login", "kaspi.kz"), otherwise "".
func HostFromText(text string) string {
	t := strings.TrimSpace(text)
	if t == "" || strings.ContainsAny(t, " \n\t") || !reLooksLikeURL.MatchString(t) {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
