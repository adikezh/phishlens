// Package notify pushes verdicts to SIEM/SOAR and back to the reporter (ТЗ §4.9):
// HMAC-signed webhook, Wazuh, TheHive 5, DFIR-IRIS and Jira delivery are
// implemented; e-mail replies remain optional.
package notify

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/store"
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
	webhooks  store.Store
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
		f.notifiers = append(f.notifiers, NewTheHive(cfg.TheHive, os.Getenv(cfg.TheHive.APIKeyEnv)))
	}
	if cfg.IRIS.Enabled {
		f.notifiers = append(f.notifiers, NewIRIS(cfg.IRIS, os.Getenv(cfg.IRIS.APIKeyEnv)))
	}
	if cfg.Jira.Enabled {
		f.notifiers = append(f.notifiers, NewJira(cfg.Jira, os.Getenv(cfg.Jira.UserEnv), os.Getenv(cfg.Jira.TokenEnv)))
	}
	return f
}

// Add registers an extra notifier (tests, plugins).
func (f *Fanout) Add(n Notifier) { f.notifiers = append(f.notifiers, n) }

// SetWebhookStore enables encrypted, org-scoped webhook subscriptions managed
// through the admin API. Static config webhooks remain supported separately.
func (f *Fanout) SetWebhookStore(st store.Store) { f.webhooks = st }

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
	if f.webhooks == nil || sub == nil {
		return
	}
	subscriptions, err := f.webhooks.ListWebhooks(ctx, sub.OrgID)
	if err != nil {
		f.log.Warn().Err(err).Str("org_id", sub.OrgID).Msg("load webhook subscriptions")
		return
	}
	for _, subscription := range subscriptions {
		if !subscription.Enabled || subscription.URL == "" || subscription.Secret == "" {
			continue
		}
		w := NewWebhook(subscription.URL, subscription.Secret)
		nctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := w.Notify(nctx, sub); err != nil {
			f.log.Warn().Err(err).Str("notifier", w.Name()).Str("webhook_id", subscription.ID).Str("id", sub.ID).Msg("notify failed")
		}
		cancel()
	}
}
