package all

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistryHasAtLeastSixtyChecks(t *testing.T) {
	r := New()
	require.GreaterOrEqual(t, r.Len(), 60)
	ids := map[string]bool{}
	for _, check := range r.Checks() {
		ids[check.ID()] = true
	}
	for _, id := range []string{
		"header.received_private_ip", "link.cloud_form", "link.data_uri",
		"content.sms_code_request", "content.card_data_request",
		"content.bank_detail_change", "content.kz_identifier",
	} {
		require.True(t, ids[id], "missing registered signal %s", id)
	}
}
