package link

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var (
	trackingPixelTag = regexp.MustCompile(`(?is)<img\b[^>]*(?:width\s*=\s*["']?1\b|height\s*=\s*["']?1\b)[^>]*>`)
	marketingWords   = []string{"unsubscribe", "opt out", "newsletter", "promotion", "sale", "скидк", "рассыл", "отпис"}
	unsubWords       = []string{"unsubscribe", "opt out", "отписаться", "отписки", "отказаться от рассылки"}
)

func trackingPixel(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	count := 0
	for _, img := range in.Mail.Images {
		if img.Width > 0 && img.Height > 0 && img.Width <= 2 && img.Height <= 2 {
			count++
		}
	}
	count += len(trackingPixelTag.FindAllString(in.Mail.HTMLBody, 3))
	if count == 0 {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDTrackingPixel, domain.CategoryLink, 8, min(1, 0.6+float64(count)*0.2), fmt.Sprintf("%d pixel-like image(s)", count), in.Lang, count)}, nil
}

func missingUnsubscribe(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if len(in.Mail.Links) == 0 {
		return nil, nil
	}
	text := strings.ToLower(in.Mail.Subject + "\n" + in.Mail.Text() + "\n" + in.Mail.HTMLBody)
	marketing := false
	for _, word := range marketingWords {
		if strings.Contains(text, word) {
			marketing = true
			break
		}
	}
	if !marketing {
		return nil, nil
	}
	for _, word := range unsubWords {
		if strings.Contains(text, word) {
			return nil, nil
		}
	}
	return []domain.Signal{signals.New(IDMissingUnsub, domain.CategoryLink, 8, 0.75, "marketing content without an unsubscribe instruction", in.Lang)}, nil
}
