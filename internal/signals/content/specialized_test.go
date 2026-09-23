package content

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func TestSpecializedCredentialAndFinanceSignals(t *testing.T) {
	in := &signals.Input{Lang: "en", Mail: &domain.ParsedMail{
		Subject:  "Verify your card",
		TextBody: "Enter your SMS OTP and CVV. New bank details are attached. IIN 990101123456.",
	}}

	sms, err := smsCodeRequest(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, sms, 1)
	card, err := cardDataRequest(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, card, 1)
	bank, err := bankDetailChange(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, bank, 1)
}
