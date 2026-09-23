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

// IRIS creates a DFIR-IRIS v2 case. The payload contains verdict metadata and
// IOCs, but never the submitted message body or raw headers.
type IRIS struct {
	cfg    config.IRIS
	apiKey string
	client *http.Client
}

type irisCase struct {
	CaseName        string `json:"case_name"`
	CaseDescription string `json:"case_description"`
	CaseCustomer    int    `json:"case_customer"`
	CaseSOCID       string `json:"case_soc_id"`
}

func NewIRIS(cfg config.IRIS, apiKey string) *IRIS {
	return &IRIS{cfg: cfg, apiKey: apiKey, client: &http.Client{Timeout: 8 * time.Second}}
}

func (i *IRIS) Name() string { return "iris" }

func (i *IRIS) Notify(ctx context.Context, sub *domain.Submission) error {
	if sub == nil || sub.Result == nil || sub.Result.Verdict.Rank() < domain.Verdict(i.cfg.MinVerdict).Rank() {
		return nil
	}
	if strings.TrimSpace(i.cfg.APIURL) == "" || strings.TrimSpace(i.apiKey) == "" {
		return fmt.Errorf("iris: api_url and api key are required")
	}
	if i.cfg.CustomerID <= 0 {
		return fmt.Errorf("iris: customer_id must be positive")
	}
	e := EventFrom(sub)
	payload := irisCase{
		CaseName:        fmt.Sprintf("PhishLens %s", e.Verdict),
		CaseDescription: fmt.Sprintf("verdict=%s score=%d confidence=%.2f signals=%s domains=%s hashes=%s", e.Verdict, e.Score, e.Confidence, strings.Join(e.Signals, ","), strings.Join(e.LinkDomains, ","), strings.Join(e.Hashes, ",")),
		CaseCustomer:    i.cfg.CustomerID,
		CaseSOCID:       e.ID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("iris: encode: %w", err)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(i.cfg.APIURL), "/")
	if !strings.HasSuffix(endpoint, "/api/v2/cases") {
		endpoint += "/api/v2/cases"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("iris: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+i.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "phishlens-iris/1")
	resp, err := i.client.Do(req)
	if err != nil {
		return fmt.Errorf("iris: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("iris: status %d", resp.StatusCode)
	}
	return nil
}
