package header

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

type listedIPRep struct{}

func (listedIPRep) IPListed(context.Context, string) (bool, string, error)     { return true, "zen", nil }
func (listedIPRep) DomainListed(context.Context, string) (bool, string, error) { return false, "", nil }
func (listedIPRep) DomainAge(context.Context, string) (time.Duration, bool, error) {
	return 0, false, nil
}

func TestReceivedIPListed(t *testing.T) {
	in := &signals.Input{Lang: "en", Rep: listedIPRep{}, Mail: &domain.ParsedMail{Received: []domain.ReceivedHop{{IP: "203.0.113.9"}}}}
	sigs, err := receivedIPListed(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, sigs, 1)
	require.Equal(t, IDReceivedIPListed, sigs[0].ID)
}

func TestBulkMailerPersonal(t *testing.T) {
	in := &signals.Input{Lang: "en", Mail: &domain.ParsedMail{Headers: map[string][]string{"X-Mailer": {"Mailchimp Campaigns"}}}}
	sigs, err := bulkMailerPersonal(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, sigs, 1)

	in.Mail.To = []domain.Address{{Addr: "a@example.test"}, {Addr: "b@example.test"}}
	sigs, err = bulkMailerPersonal(context.Background(), in)
	require.NoError(t, err)
	require.Empty(t, sigs)
}
