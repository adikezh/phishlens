package content

import (
	"context"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var (
	smsCodePattern  = regexp.MustCompile(`(?i)(?:sms|text message|one[- ]time|otp|код из смс|одноразовый код|растау коды)`)
	cardDataPattern = regexp.MustCompile(`(?i)(?:card|credit card|cvv|cvc|карты|номер карты|срок действия)`)
)

func smsCodeRequest(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	text := fullText(in)
	if !smsCodePattern.MatchString(text) {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDSMSCodeRequest, domain.CategoryContent, 12, 0.85,
		"request for SMS/OTP code", in.Lang)}, nil
}

func cardDataRequest(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	text := fullText(in)
	if !cardDataPattern.MatchString(text) {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDCardDataRequest, domain.CategoryContent, 12, 0.8,
		strings.TrimSpace("request for payment-card data"), in.Lang)}, nil
}
