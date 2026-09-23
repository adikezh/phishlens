package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// TheHive creates an alert with observables (domains, URLs, hashes) — F-4.6.2.
type TheHive struct {
	cfg    config.TheHive
	apiKey string
	client *http.Client
}

type theHiveAlert struct {
	Type        string              `json:"type"`
	Source      string              `json:"source"`
	SourceRef   string              `json:"sourceRef"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Severity    int                 `json:"severity"`
	Observables []theHiveObservable `json:"observables,omitempty"`
}

type theHiveObservable struct {
	DataType string `json:"dataType"`
	Data     string `json:"data"`
}

func (t *TheHive) Name() string { return "thehive" }

// NewTheHive builds a TheHive 5 alert notifier. APIURL may be either the
// server base URL or the full /api/v1/alert endpoint.
func NewTheHive(cfg config.TheHive, apiKey string) *TheHive {
	return &TheHive{cfg: cfg, apiKey: apiKey, client: &http.Client{Timeout: 8 * time.Second}}
}

// Notify implements Notifier.
func (t *TheHive) Notify(ctx context.Context, sub *domain.Submission) error {
	if sub == nil || sub.Result == nil {
		return nil
	}
	if sub.Result.Verdict.Rank() < domain.Verdict(t.cfg.MinVerdict).Rank() {
		return nil
	}
	if strings.TrimSpace(t.cfg.APIURL) == "" {
		return fmt.Errorf("thehive: api_url is not configured")
	}
	if strings.TrimSpace(t.apiKey) == "" {
		return fmt.Errorf("thehive: api key is not configured")
	}
	e := EventFrom(sub)
	alert := theHiveAlert{
		Type:        "phishlens",
		Source:      "phishlens",
		SourceRef:   e.ID,
		Title:       fmt.Sprintf("PhishLens %s (%d/100)", e.Verdict, e.Score),
		Description: fmt.Sprintf("verdict=%s score=%d confidence=%.2f signals=%s", e.Verdict, e.Score, e.Confidence, strings.Join(e.Signals, ",")),
		Severity:    theHiveSeverity(e.Verdict),
	}
	for _, value := range e.LinkDomains {
		alert.Observables = append(alert.Observables, theHiveObservable{DataType: "domain", Data: value})
	}
	if e.SenderDomain != "" {
		alert.Observables = append(alert.Observables, theHiveObservable{DataType: "domain", Data: e.SenderDomain})
	}
	for _, hash := range e.Hashes {
		if hash != "" {
			alert.Observables = append(alert.Observables, theHiveObservable{DataType: "hash", Data: hash})
		}
	}
	body, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("thehive: encode: %w", err)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(t.cfg.APIURL), "/")
	if !strings.HasSuffix(endpoint, "/api/v1/alert") {
		endpoint += "/api/v1/alert"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("thehive: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+t.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "phishlens-thehive/1")
	if org := strings.TrimSpace(t.cfg.Organisation); org != "" {
		req.Header.Set("X-Organisation", org)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("thehive: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("thehive: status %d", resp.StatusCode)
	}
	return nil
}

func theHiveSeverity(v domain.Verdict) int {
	switch v {
	case domain.VerdictPhishing:
		return 3
	case domain.VerdictSuspicious:
		return 2
	default:
		return 1
	}
}
