package reputation

import (
	"context"
	"time"
)

// rdapAge — TODO(D-01): openrdap/rdap → events[eventAction=registration].eventDate;
// fall back to WHOIS for .kz (KazNIC) where RDAP is incomplete.
func rdapAge(_ context.Context, _ string) (time.Duration, error) {
	return 0, ErrNotImplemented
}
