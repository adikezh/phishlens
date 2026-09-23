// Package sandbox drives a separately hosted headless Chromium instance.
// The browser endpoint must be isolated by deployment policy (normally a
// network-restricted container with an egress proxy).
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/phishlens/phishlens/internal/netutil"
)

// ErrNotImplemented is retained for compatibility with callers that used the
// old disabled runner. Enabled deployments return concrete errors instead.
var ErrNotImplemented = errors.New("sandbox: not implemented")

const defaultTimeout = 15 * time.Second

// Result is the detonation outcome.
type Result struct {
	FinalURL      string   `json:"final_url"`
	Redirects     []string `json:"redirects,omitempty"`
	HasLoginForm  bool     `json:"has_login_form"`
	ScreenshotPNG []byte   `json:"-"`
	Title         string   `json:"title,omitempty"`
	BrandMatch    string   `json:"brand_match,omitempty"`
}

// Runner detonates URLs.
type Runner interface {
	Detonate(ctx context.Context, url string) (*Result, error)
}

// Chrome is a client for a remote Chrome DevTools endpoint. It never launches
// a browser in the PhishLens process, so the browser can be isolated by the
// operator independently of the API container.
type Chrome struct {
	Endpoint   string
	Screenshot bool
	Timeout    time.Duration
	UserAgent  string
	Resolver   *net.Resolver
}

// New constructs a remote Chromium runner.
func New(endpoint string, screenshot bool) *Chrome {
	return &Chrome{Endpoint: endpoint, Screenshot: screenshot, Timeout: defaultTimeout,
		UserAgent: "PhishLens-Sandbox/1.0", Resolver: net.DefaultResolver}
}

// Detonate opens a fresh target, clears browser cookies, and collects only
// rendered metadata plus an optional screenshot. The destination is resolved
// before navigation and private/link-local/metadata addresses are rejected.
func (r *Chrome) Detonate(parent context.Context, rawURL string) (*Result, error) {
	target, err := validatePublicURL(parent, r.Resolver, rawURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.Endpoint) == "" {
		return nil, fmt.Errorf("sandbox: remote Chrome endpoint is empty")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, r.Endpoint)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	var details struct {
		URL          string `json:"url"`
		Title        string `json:"title"`
		HasLoginForm bool   `json:"hasLoginForm"`
	}
	var screenshot []byte
	ua := r.UserAgent
	if ua == "" {
		ua = "PhishLens-Sandbox/1.0"
	}
	actions := chromedp.Tasks{
		network.ClearBrowserCookies(),
		network.SetCacheDisabled(true),
		emulation.SetUserAgentOverride(ua),
		chromedp.Navigate(target.String()),
		chromedp.Sleep(250 * time.Millisecond),
		chromedp.Evaluate(`({url: location.href, title: document.title, hasLoginForm: !!document.querySelector('input[type="password"]')})`, &details),
	}
	if r.Screenshot {
		actions = append(actions, chromedp.FullScreenshot(&screenshot, 70))
	}
	if err := chromedp.Run(browserCtx, actions...); err != nil {
		return nil, fmt.Errorf("sandbox: detonate %q: %w", target.String(), err)
	}
	if details.URL == "" {
		details.URL = target.String()
	}
	result := &Result{FinalURL: details.URL, HasLoginForm: details.HasLoginForm, Title: details.Title, ScreenshotPNG: screenshot}
	if details.URL != target.String() {
		result.Redirects = []string{target.String()}
	}
	return result, nil
}

// Noop is used when sandbox.enabled=false.
type Noop struct{}

// Detonate implements Runner.
func (Noop) Detonate(_ context.Context, _ string) (*Result, error) { return nil, ErrNotImplemented }

func validatePublicURL(ctx context.Context, resolver *net.Resolver, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("sandbox: invalid or unsafe URL")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" {
		return nil, fmt.Errorf("sandbox: local hostname is not allowed")
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var addrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IP{ip}
	} else {
		resolved, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("sandbox: resolve %q: %w", host, err)
		}
		addrs = resolved
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("sandbox: host %q has no address", host)
	}
	for _, ip := range addrs {
		if netutil.IsPrivateOrLocal(ip) {
			return nil, fmt.Errorf("sandbox: destination %q resolves to private/local address %s", host, ip)
		}
	}
	return u, nil
}
