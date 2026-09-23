package reputation

import "context"

// urlhausLookup — TODO(R-02): POST https://urlhaus-api.abuse.ch/v1/host/ {host} → query_status.
// Consider the hourly bulk dump (urlhaus.abuse.ch/downloads/text/) loaded into memory instead of per-query calls.
func urlhausLookup(_ context.Context, _ string) (bool, error) {
	return false, ErrNotImplemented
}
