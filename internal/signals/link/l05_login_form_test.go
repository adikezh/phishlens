package link

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/sandbox"
	"github.com/phishlens/phishlens/internal/signals"
)

type fakeSandbox struct{}

func (fakeSandbox) Detonate(_ context.Context, url string) (*sandbox.Result, error) {
	return &sandbox.Result{FinalURL: url + "/login", HasLoginForm: true}, nil
}

func TestLoginFormOnForeignDomain(t *testing.T) {
	in := &signals.Input{Lang: "en", Sandbox: fakeSandbox{}, Mail: &domain.ParsedMail{
		Links: []domain.Link{{Href: "https://evil.example/login", Domain: "evil.example"}},
	}}
	out, err := loginForm(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, IDLoginForm, out[0].ID)
}
