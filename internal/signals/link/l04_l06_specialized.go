package link

import (
	"context"
	"net/url"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var cloudFormHosts = map[string]bool{
	"docs.google.com": true, "forms.google.com": true, "forms.office.com": true,
	"typeform.com": true, "www.typeform.com": true, "jotform.com": true,
	"www.jotform.com": true,
}

func dataURI(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	for _, l := range in.Mail.Links {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l.Href)), "data:") {
			return []domain.Signal{signals.New(IDDataURI, domain.CategoryLink, 18, 0.9, l.Href, in.Lang, "data: URI")}, nil
		}
	}
	return nil, nil
}

func cloudForm(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	text := strings.ToLower(in.Mail.Subject + "\n" + in.Mail.Text())
	credentialWords := []string{"password", "passcode", "парол", "код", "login", "войд", "cvv"}
	for _, l := range in.Mail.Links {
		u, err := url.Parse(l.Href)
		if err != nil || !cloudFormHosts[strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))] {
			continue
		}
		for _, word := range credentialWords {
			if strings.Contains(text, word) {
				return []domain.Signal{signals.New(IDCloudForm, domain.CategoryLink, 18, 0.85,
					l.Href, in.Lang, u.Hostname())}, nil
			}
		}
	}
	return nil, nil
}
