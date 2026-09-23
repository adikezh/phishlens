package authcheck

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
)

type fakeResolver struct {
	txt map[string][]string
}

func (r fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if values, ok := r.txt[name]; ok {
		return values, nil
	}
	return nil, &net.DNSError{Err: "not found", Name: name, IsNotFound: true}
}
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error)        { return nil, nil }
func (fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) { return nil, nil }
func (fakeResolver) LookupAddr(context.Context, string) ([]string, error)       { return nil, nil }

func TestVerifyOwnAuthSPFAndDMARC(t *testing.T) {
	mail := &domain.ParsedMail{
		From:       domain.Address{Addr: "sender@example.com", Domain: "example.com"},
		ReturnPath: domain.Address{Addr: "sender@example.com", Domain: "example.com"},
		Received:   []domain.ReceivedHop{{From: "mx.example.net", IP: "203.0.113.9"}},
		Raw:        []byte("From: sender@example.com\r\n\r\nhello\r\n"),
	}
	r := fakeResolver{txt: map[string][]string{
		"example.com":        {"v=spf1 ip4:203.0.113.9 -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}}

	got, err := Verify(context.Background(), mail, r)
	require.NoError(t, err)
	require.Equal(t, "own", got.Source)
	require.Equal(t, domain.AuthPass, got.SPF)
	require.Equal(t, domain.AuthNone, got.DKIM)
	require.Equal(t, domain.AuthPass, got.DMARC)
}

func TestVerifyOwnAuthFailsUnauthorisedSender(t *testing.T) {
	mail := &domain.ParsedMail{
		From:     domain.Address{Addr: "sender@example.com", Domain: "example.com"},
		Received: []domain.ReceivedHop{{IP: "203.0.113.10"}},
		Raw:      []byte("From: sender@example.com\r\n\r\nhello\r\n"),
	}
	r := fakeResolver{txt: map[string][]string{
		"example.com":        {"v=spf1 ip4:203.0.113.9 -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}}

	got, err := Verify(context.Background(), mail, r)
	require.NoError(t, err)
	require.Equal(t, domain.AuthFail, got.SPF)
	require.Equal(t, domain.AuthFail, got.DMARC)
}

func TestVerifyOwnAuthNoDMARCRecordIsUnknown(t *testing.T) {
	mail := &domain.ParsedMail{
		From:     domain.Address{Addr: "sender@example.com", Domain: "example.com"},
		Received: []domain.ReceivedHop{{IP: "203.0.113.9"}},
		Raw:      []byte("From: sender@example.com\r\n\r\nhello\r\n"),
	}
	r := fakeResolver{txt: map[string][]string{
		"example.com": {"v=spf1 ip4:203.0.113.9 -all"},
	}}

	got, err := Verify(context.Background(), mail, r)
	require.NoError(t, err)
	require.Equal(t, domain.AuthPass, got.SPF)
	require.Equal(t, domain.AuthNone, got.DMARC)
}
