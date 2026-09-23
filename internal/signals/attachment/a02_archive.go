package attachment

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/signals"
)

// A-02: password-protected archive, or an executable/script inside the listing.
func archive(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	var out []domain.Signal
	for _, a := range in.Mail.Attachments {
		if !a.IsArchive {
			continue
		}
		if a.PasswordProtected {
			out = append(out, signals.New(IDArchiveEncrypted, domain.CategoryAttachment, 25, 0.9, a.Name, in.Lang, a.Name))
		}
		for _, n := range a.NestedNames {
			if _, bad := in.Data.DangerousExts[parse.Ext(n)]; bad || strings.ContainsRune(n, '\u202E') {
				out = append(out, signals.New(IDArchiveExecutable, domain.CategoryAttachment, 30, 0.95, a.Name+" -> "+n, in.Lang, a.Name, n))
				break
			}
		}
	}
	return out, nil
}
