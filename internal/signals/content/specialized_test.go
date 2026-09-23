package content

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/data"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/refdata"
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

func TestBECPatternLocalesAndNegatives(t *testing.T) {
	rd, err := refdata.Load(data.FS, "")
	require.NoError(t, err)
	tests := []struct {
		name, lang, display, body string
		want                      bool
	}{
		{"ru executive request", "ru", "Генеральный директор", "Я на встрече, никому не сообщай. Оплати сегодня.", true},
		{"en executive request", "en", "CEO", "I am in a meeting, keep this confidential. Wire transfer today.", true},
		{"kz executive request", "kz", "Бас директор", "Кездесудемін, ешкімге айтпа. Шұғыл аударым жаса.", true},
		{"ordinary finance discussion", "ru", "Бухгалтерия", "В бухгалтерском отделе обсудили оплату счета и реквизиты.", false},
		{"authority without secrecy", "en", "CEO", "Please review the invoice payment in the normal process.", false},
		{"secrecy without request", "kz", "Сотрудник", "Кездесудемін, ешкімге айтпа.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &signals.Input{Lang: tt.lang, Data: rd, Mail: &domain.ParsedMail{
				From: domain.Address{Display: tt.display}, TextBody: tt.body,
			}}
			got, err := becPattern(context.Background(), in)
			require.NoError(t, err)
			require.Equal(t, tt.want, len(got) == 1, "signals=%v", got)
		})
	}
}
