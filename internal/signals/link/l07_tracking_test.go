package link

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func TestTrackingPixelAndMissingUnsubscribe(t *testing.T) {
	in := &signals.Input{Lang: "en", Mail: &domain.ParsedMail{
		Subject:  "Sale newsletter",
		HTMLBody: `<img src="https://tracker.example/p.gif" width="1" height="1"><a href="https://shop.example">Buy</a>`,
		Links:    []domain.Link{{Href: "https://shop.example", Domain: "shop.example"}},
		Images:   []domain.InlineImage{{Width: 1, Height: 1}},
	}}
	pixel, err := trackingPixel(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, pixel, 1)
	unsub, err := missingUnsubscribe(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, unsub, 1)
}

func TestMissingUnsubscribeIgnoresTransactionalMessage(t *testing.T) {
	in := &signals.Input{Lang: "en", Mail: &domain.ParsedMail{
		Subject:  "Your receipt",
		TextBody: "Your order is ready: https://shop.example/order",
		Links:    []domain.Link{{Href: "https://shop.example/order", Domain: "shop.example"}},
	}}
	sigs, err := missingUnsubscribe(context.Background(), in)
	require.NoError(t, err)
	require.Empty(t, sigs)
}
