package attachment

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func filterAttachmentSignal(id string, fn func(context.Context, *signals.Input) ([]domain.Signal, error), ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	out, err := fn(ctx, in)
	if err != nil {
		return nil, err
	}
	filtered := make([]domain.Signal, 0, len(out))
	for _, s := range out {
		if s.ID == id {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

func dangerousExtOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterAttachmentSignal(IDDangerousExt, dangerousName, ctx, in)
}
func doubleExtOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterAttachmentSignal(IDDoubleExt, dangerousName, ctx, in)
}
func rtlOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterAttachmentSignal(IDRTLOverride, dangerousName, ctx, in)
}
func archiveEncryptedOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterAttachmentSignal(IDArchiveEncrypted, archive, ctx, in)
}
func archiveExecutableOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterAttachmentSignal(IDArchiveExecutable, archive, ctx, in)
}
