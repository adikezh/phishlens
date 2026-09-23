// Package review is the analyst queue (ТЗ §4.6, Business): list/filter
// submissions, group into campaigns, apply actions (confirm, reject, escalate,
// block domain, create incident, reply). Feedback labels feed `weights tune`.
package review

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/store"
)

// ErrNotImplemented marks stubbed actions.
var ErrNotImplemented = errors.New("review: not implemented")

// Campaign groups submissions sharing sender domain / links / subject (F-4.6.1).
type Campaign struct {
	Key         string               `json:"key"`
	Count       int                  `json:"count"`
	Verdicts    map[string]int       `json:"verdicts"`
	Submissions []*domain.Submission `json:"submissions"`
}

// CampaignKey derives the grouping key: sender domain + sorted link domains + normalised subject.
func CampaignKey(m *domain.ParsedMail) string {
	if m == nil {
		return ""
	}
	links := append([]string(nil), m.LinkDomains()...)
	sort.Strings(links)
	subject := strings.ToLower(strings.Join(strings.Fields(m.Subject), " "))
	if len(subject) > 40 {
		subject = subject[:40]
	}
	return strings.Join([]string{m.From.Domain, strings.Join(links, ","), subject}, "|")
}

// Queue exposes analyst operations.
type Queue struct {
	st store.Store
}

// NewQueue binds the queue to a store.
func NewQueue(st store.Store) *Queue { return &Queue{st: st} }

// List returns submissions matching the filter.
func (q *Queue) List(ctx context.Context, f store.SubmissionFilter) ([]*domain.Submission, error) {
	return q.st.ListSubmissions(ctx, f)
}

// Campaigns groups a list of submissions.
func Campaigns(subs []*domain.Submission) []Campaign {
	byKey := map[string]*Campaign{}
	for _, s := range subs {
		key := CampaignKey(s.Message)
		c, ok := byKey[key]
		if !ok {
			c = &Campaign{Key: key, Verdicts: map[string]int{}}
			byKey[key] = c
		}
		c.Count++
		if s.Result != nil {
			c.Verdicts[string(s.Result.Verdict)]++
		}
		c.Submissions = append(c.Submissions, s)
	}
	out := make([]Campaign, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// SetStatus records the analyst decision (confirm/reject/escalate) and audits it.
func (q *Queue) SetStatus(ctx context.Context, id string, status domain.Status, actor string) error {
	if err := q.st.UpdateSubmissionStatus(ctx, id, status, actor); err != nil {
		return err
	}
	return q.st.Audit(ctx, store.AuditEntry{Actor: actor, Action: "submission.review", Target: id, Details: string(status)})
}

// BlockDomain — TODO(F-4.6.2): add to org blocklist + fire "block" webhook to gateway/proxy/DNS filter.
func (q *Queue) BlockDomain(_ context.Context, _ string, _ string) error { return ErrNotImplemented }

// CreateIncident — TODO(F-4.6.2): Wazuh custom event / TheHive / IRIS / Jira.
func (q *Queue) CreateIncident(_ context.Context, _ string) error { return ErrNotImplemented }
