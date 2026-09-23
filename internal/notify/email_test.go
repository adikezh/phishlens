package notify

import (
	"strings"
	"testing"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestReplyMessageDoesNotQuoteOriginal(t *testing.T) {
	sub := &domain.Submission{Result: &domain.Analysis{Verdict: domain.VerdictPhishing, Score: 88, Signals: []domain.Signal{{Explanation: "опасный\r\nX-Injected: yes"}}}}
	message := replyMessage("soc@example.test", "user@example.test", sub)
	require.Contains(t, message, "Вердикт: phishing")
	require.Contains(t, message, "опасный X-Injected: yes")
	require.NotContains(t, message, "Original body")
	require.False(t, strings.Contains(message, "\r\nX-Injected:"))
}
