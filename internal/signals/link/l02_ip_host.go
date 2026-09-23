package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// L-02: link host is a raw IP address, or a non-standard port is used.
func ipHost(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	seenPort := false
	for _, l := range in.Mail.Links {
		if l.IsIP {
			out = append(out, signals.New(IDIPHost, domain.CategoryLink, 20, 0.9, l.Href, in.Lang, l.Href))
		}
		if l.Port != "" && l.Port != "80" && l.Port != "443" && !seenPort {
			seenPort = true
			out = append(out, signals.New(IDNonstandardPort, domain.CategoryLink, 8, 0.7, l.Href, in.Lang, l.Port))
		}
		if len(out) >= 4 {
			break
		}
	}
	return out, nil
}
