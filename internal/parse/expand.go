package parse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
)

// expandShorteners resolves known shorteners without downloading page bodies.
// Every initial and redirected host is checked against private/local ranges.
func (p *Parser) expandShorteners(ctx context.Context, pm *domain.ParsedMail) {
	if !p.ExpandShorteners || p.MaxRedirects <= 0 || p.ExpansionTimeout <= 0 {
		return
	}
	client := &http.Client{Timeout: p.ExpansionTimeout}
	for i := range pm.Links {
		link := &pm.Links[i]
		if !link.IsShortener || link.Href == "" {
			continue
		}
		redirects, err := expandShortener(ctx, link.Href, client, p.MaxRedirects)
		if err == nil && len(redirects) > 0 {
			link.Redirects = redirects
		}
	}
}

func expandShortener(ctx context.Context, href string, client *http.Client, maxRedirects int) ([]string, error) {
	u, err := normalizeHTTPURL(href)
	if err != nil {
		return nil, err
	}
	if err := publicURL(u); err != nil {
		return nil, err
	}
	redirects := make([]string, 0, maxRedirects+1)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if err := publicURL(req.URL); err != nil {
			return err
		}
		redirects = append(redirects, req.URL.String())
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "phishlens-link-check/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shortener expansion: %w", err)
	}
	resp.Body.Close()
	return redirects, nil
}

func normalizeHTTPURL(href string) (*url.URL, error) {
	raw := strings.TrimSpace(href)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("shortener expansion: invalid URL")
	}
	return u, nil
}

func publicURL(u *url.URL) error {
	if u == nil || u.Hostname() == "" {
		return fmt.Errorf("shortener expansion: missing host")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if netutil.IsPrivateOrLocal(ip) {
			return fmt.Errorf("shortener expansion: private host denied")
		}
		return nil
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return fmt.Errorf("shortener expansion: local host denied")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("shortener expansion: host lookup failed")
	}
	for _, ip := range ips {
		if netutil.IsPrivateOrLocal(ip) {
			return fmt.Errorf("shortener expansion: private host denied")
		}
	}
	return nil
}
