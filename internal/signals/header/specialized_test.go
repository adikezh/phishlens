package header

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func TestReceivedPrivateIPIsLowConfidence(t *testing.T) {
	sigs, err := receivedPrivateIP(context.Background(), &signals.Input{
		Lang: "en", Mail: &domain.ParsedMail{Received: []domain.ReceivedHop{{IP: "10.0.0.4"}}},
	})
	require.NoError(t, err)
	require.Len(t, sigs, 1)
	require.Equal(t, IDReceivedPrivateIP, sigs[0].ID)
	require.Equal(t, 3, sigs[0].Weight)
}
