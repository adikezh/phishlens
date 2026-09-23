package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// Wazuh sends a custom event when verdict ≥ min_verdict (F-4.9.1).
// The configured APIURL is the Wazuh event-ingestion endpoint (or an internal
// relay endpoint). The event contains only verdict, signals and IOC metadata.
type Wazuh struct {
	cfg      config.Wazuh
	password string
	client   *http.Client
}

// NewWazuh builds the notifier.
func NewWazuh(cfg config.Wazuh, password string) *Wazuh {
	return &Wazuh{cfg: cfg, password: password, client: &http.Client{Timeout: 8 * time.Second}}
}

func (w *Wazuh) Name() string { return "wazuh" }

// Notify implements Notifier.
func (w *Wazuh) Notify(ctx context.Context, sub *domain.Submission) error {
	if sub.Result == nil {
		return nil
	}
	if sub.Result.Verdict.Rank() < domain.Verdict(w.cfg.MinVerdict).Rank() {
		return nil
	}
	if strings.TrimSpace(w.cfg.APIURL) == "" {
		return fmt.Errorf("wazuh: api_url is not configured")
	}
	body, err := json.Marshal(map[string]any{
		"integration": "phishlens",
		"event":       EventFrom(sub),
	})
	if err != nil {
		return fmt.Errorf("wazuh: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.APIURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("wazuh: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "phishlens-wazuh/1")
	req.SetBasicAuth(w.cfg.User, w.password)
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("wazuh: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("wazuh: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
