// Package all registers every signal category in one call.
package all

import (
	"github.com/phishlens/phishlens/internal/signals"
	"github.com/phishlens/phishlens/internal/signals/attachment"
	"github.com/phishlens/phishlens/internal/signals/auth"
	"github.com/phishlens/phishlens/internal/signals/brand"
	"github.com/phishlens/phishlens/internal/signals/content"
	domainsig "github.com/phishlens/phishlens/internal/signals/domain"
	"github.com/phishlens/phishlens/internal/signals/header"
	"github.com/phishlens/phishlens/internal/signals/link"
	"github.com/phishlens/phishlens/internal/signals/reputation"
	"github.com/phishlens/phishlens/internal/signals/semantic"
)

// Register wires all categories into r.
func Register(r *signals.Registry) {
	header.Register(r)
	auth.Register(r)
	domainsig.Register(r)
	link.Register(r)
	attachment.Register(r)
	content.Register(r)
	brand.Register(r)
	reputation.Register(r)
	semantic.Register(r)
}

// New returns a registry with everything registered.
func New() *signals.Registry {
	r := signals.NewRegistry()
	Register(r)
	return r
}
