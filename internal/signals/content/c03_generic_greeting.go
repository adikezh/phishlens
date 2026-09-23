package content

import (
	"context"
	"regexp"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var reGenericGreeting = regexp.MustCompile(`(?i)^\s*(уважаемый\s+(клиент|пользователь|абонент|гражданин)|дорогой\s+(клиент|пользователь)|dear\s+(customer|user|client|member|valued customer|sir/madam)|құрметті\s+(клиент|пайдаланушы))`)

// C-03: impersonal greeting while a brand that knows the customer's name is imitated.
func genericGreeting(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Brand == nil || in.Brand.Official {
		return nil, nil
	}
	m := reGenericGreeting.FindString(in.Mail.Text())
	if m == "" {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDGenericGreeting, domain.CategoryContent, 8, 0.7, m, in.Lang, m, in.Brand.Name)}, nil
}
