package reputation

import "context"

// openphishLookup — TODO(D-02): periodic download of https://openphish.com/feed.txt into a host set.
func openphishLookup(_ context.Context, _ string) (bool, error) {
	return false, ErrNotImplemented
}
