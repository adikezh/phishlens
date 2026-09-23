package header

import (
	"context"
	"net"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func filterHeaderSignal(id string, ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	out, err := messageID(ctx, in)
	if err != nil {
		return nil, err
	}
	for _, s := range out {
		if s.ID == id {
			return []domain.Signal{s}, nil
		}
	}
	return nil, nil
}

func messageIDMismatch(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterHeaderSignal(IDMessageIDMismatch, ctx, in)
}

func messageIDMissing(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterHeaderSignal(IDMessageIDMissing, ctx, in)
}

// receivedPrivateIP records a low-confidence hygiene issue. Private hops are
// common in internal mail, so this never implies phishing by itself.
func receivedPrivateIP(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	for _, hop := range in.Mail.Received {
		ip := net.ParseIP(hop.IP)
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return []domain.Signal{signals.New(IDReceivedPrivateIP, domain.CategoryHeader, 3, 0.5, hop.IP, in.Lang, hop.IP)}, nil
		}
	}
	return nil, nil
}
