// Package sandbox detonates links in headless Chromium inside an isolated
// container (F-4.9.3, Business): final URL, screenshot, login-form detection,
// brand similarity of the rendered page.
// TODO: chromedp against sandbox.url; SSRF guard (netutil.IsPrivateOrLocal) before navigation;
// no cookies, fixed UA, 15 s budget, screenshot pHash vs brands.
package sandbox

import (
	"context"
	"errors"
)

// ErrNotImplemented marks the stub.
var ErrNotImplemented = errors.New("sandbox: not implemented")

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

// Noop is used when sandbox.enabled=false.
type Noop struct{}

// Detonate implements Runner.
func (Noop) Detonate(_ context.Context, _ string) (*Result, error) { return nil, ErrNotImplemented }
