package attachment

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/signals"
)

var docExts = map[string]bool{"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "jpg": true, "jpeg": true, "png": true, "txt": true, "ppt": true, "pptx": true}

// A-01: dangerous extension, double extension (invoice.pdf.exe), RTLO in the name.
func dangerousName(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	var out []domain.Signal
	for _, a := range in.Mail.Attachments {
		name := a.Name
		if strings.ContainsRune(name, '\u202E') || strings.ContainsRune(name, '\u202B') {
			out = append(out, signals.New(IDRTLOverride, domain.CategoryAttachment, 30, 1, name, in.Lang, name))
			continue
		}
		if _, bad := in.Data.DangerousExts[a.Ext]; bad {
			out = append(out, signals.New(IDDangerousExt, domain.CategoryAttachment, 30, 0.95, name, in.Lang, name))
		}
		if parts := strings.Split(strings.ToLower(name), "."); len(parts) >= 3 {
			inner := parts[len(parts)-2]
			if _, bad := in.Data.DangerousExts[parse.Ext(name)]; bad && docExts[inner] {
				out = append(out, signals.New(IDDoubleExt, domain.CategoryAttachment, 25, 0.95, name, in.Lang, name))
			}
		}
	}
	return out, nil
}
