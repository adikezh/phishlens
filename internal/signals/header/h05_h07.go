package header

import (
	"context"
	"fmt"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var bulkMailers = []string{"mailchimp", "sendgrid", "mailgun", "constant contact", "campaign monitor", "salesforce", "hubspot", "marketo", "amazon ses", "sendinblue", "brevo", "klaviyo"}

func receivedIPListed(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Rep == nil {
		return nil, nil
	}
	for _, hop := range in.Mail.Received {
		if hop.IP == "" {
			continue
		}
		listed, source, err := in.Rep.IPListed(ctx, hop.IP)
		if err != nil {
			return nil, err
		}
		if listed {
			s := signals.New(IDReceivedIPListed, domain.CategoryHeader, 30, 0.9, hop.IP, in.Lang, hop.IP, source)
			s.Source = domain.SourceTI
			return []domain.Signal{s}, nil
		}
	}
	return nil, nil
}

func bulkMailerPersonal(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if len(in.Mail.To) > 1 {
		return nil, nil
	}
	value := strings.ToLower(in.Mail.Header("X-Mailer") + " " + in.Mail.Header("User-Agent"))
	for _, mailer := range bulkMailers {
		if strings.Contains(value, mailer) {
			return []domain.Signal{signals.New(IDBulkMailer, domain.CategoryHeader, 8, 0.75, fmt.Sprintf("%s on a personal-looking message", mailer), in.Lang, mailer)}, nil
		}
	}
	return nil, nil
}
