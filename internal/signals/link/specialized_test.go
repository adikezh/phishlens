package link

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func TestCloudFormAndDataURISignals(t *testing.T) {
	in := &signals.Input{Lang: "en", Mail: &domain.ParsedMail{
		Subject: "Password verification",
		TextBody: "Enter your password at https://forms.google.com/d/e/abc or use " +
			"data:text/html;base64,Zm9v",
		Links: []domain.Link{
			{Href: "https://forms.google.com/d/e/abc", Domain: "forms.google.com"},
			{Href: "data:text/html;base64,Zm9v"},
		},
	}}
	cloud, err := cloudForm(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, cloud, 1)
	data, err := dataURI(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, data, 1)
}
