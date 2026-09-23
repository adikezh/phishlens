// Package notify pushes verdicts to SIEM/SOAR and back to the reporter (ТЗ §4.9):
// HMAC-signed webhook and configured Wazuh HTTP delivery are implemented;
// TheHive/IRIS/Jira and e-mail replies remain optional integrations.
package notify

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// ErrNotImplemented marks stubbed integrations.
var ErrNotImplemented = errors.New("notify: not implemented")

// Event is the outbound payload (no bodies — only IOCs and the verdict).
type Event struct {
	Type         string            `json:"type"` // phishlens.analysis
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	Channel      domain.Channel    `json:"channel"`
	Verdict      domain.Verdict    `json:"verdict"`
	Score        int               `json:"score"`
	Confidence   float64           `json:"confidence"`
	AttackType   domain.AttackType `json:"attack_type"`
	Brand        string            `json:"brand,omitempty"`
	SenderDomain string            `json:"sender_domain,omitempty"`
	ReplyDomain  string            `json:"reply_domain,omitempty"`
	LinkDomains  []string          `json:"link_domains,omitempty"`
	Hashes       []string          `json:"attachment_sha256,omitempty"`
	Signals      []string          `json:"signals"`
	OrgID        string            `json:"org_id,omitempty"`
}

// EventFrom builds an Event from a submission.
func EventFrom(sub *domain.Submission) Event {
	e := Event{Type: "phishlens.analysis", ID: sub.ID, Timestamp: sub.ReceivedAt, Channel: sub.Channel, OrgID: sub.OrgID}
	if a := sub.Result; a != nil {
		e.Verdict, e.Score, e.Confidence, e.AttackType = a.Verdict, a.Score, a.Confidence, a.AttackType
		if a.Brand != nil {
			e.Brand = a.Brand.Name
		}
		for _, s := range a.Signals {
			e.Signals = append(e.Signals, s.ID)
		}
	}
	if m := sub.Message; m != nil {
		e.SenderDomain, e.ReplyDomain = m.From.Domain, m.ReplyTo.Domain
		e.LinkDomains = m.LinkDomains()
		for _, at := range m.Attachments {
			e.Hashes = append(e.Hashes, at.SHA256)
		}
	}
	return e
}

// Notifier delivers an event.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, sub *domain.Submission) error
}

// Fanout sends to every configured notifier, logging failures.
type Fanout struct {
	notifiers []Notifier
	log       zerolog.Logger
}

// NewFanout builds notifiers from config.
func NewFanout(cfg config.Integrations, log zerolog.Logger) *Fanout {
	f := &Fanout{log: log}
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		f.notifiers = append(f.notifiers, NewWebhook(cfg.Webhook.URL, os.Getenv(cfg.Webhook.SecretEnv)))
	}
	if cfg.Wazuh.Enabled {
		f.notifiers = append(f.notifiers, NewWazuh(cfg.Wazuh, os.Getenv(cfg.Wazuh.PasswordEnv)))
	}
	if cfg.TheHive.Enabled {
		f.notifiers = append(f.notifiers, &TheHive{})
	}
	return f
}

// Add registers an extra notifier (tests, plugins).
func (f *Fanout) Add(n Notifier) { f.notifiers = append(f.notifiers, n) }

// Notify delivers to all; safe to call in a goroutine.
func (f *Fanout) Notify(ctx context.Context, sub *domain.Submission) {
	if f == nil {
		return
	}
	for _, n := range f.notifiers {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := n.Notify(ctx, sub); err != nil && !errors.Is(err, ErrNotImplemented) {
			f.log.Warn().Err(err).Str("notifier", n.Name()).Str("id", sub.ID).Msg("notify failed")
		}
		cancel()
	}
}
