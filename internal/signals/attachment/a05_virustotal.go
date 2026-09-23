package attachment

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

type hashLookup interface {
	FileHashListed(context.Context, string) (bool, string, error)
}

// A-05 checks attachment hashes only; the attachment bytes are never uploaded.
func virusTotal(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	lookup, ok := in.Rep.(hashLookup)
	if !ok {
		return nil, nil
	}
	var out []domain.Signal
	var firstErr error
	for _, a := range in.Mail.Attachments {
		if a.SHA256 == "" {
			continue
		}
		listed, source, err := lookup.FileHashListed(ctx, a.SHA256)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if listed {
			out = append(out, signals.New(IDVirusTotal, domain.CategoryAttachment, 35, 0.95, a.Name+" @ "+source, in.Lang, a.Name, source))
		}
	}
	return out, firstErr
}
