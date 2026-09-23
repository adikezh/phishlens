package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// Jira creates a Jira REST issue with an Atlassian Document Format description.
// It intentionally sends only verdict metadata and IOCs, never message bodies.
type Jira struct {
	cfg    config.Jira
	user   string
	token  string
	client *http.Client
}

type jiraIssue struct {
	Fields jiraFields `json:"fields"`
}

type jiraFields struct {
	Project     jiraProject `json:"project"`
	IssueType   jiraName    `json:"issuetype"`
	Summary     string      `json:"summary"`
	Labels      []string    `json:"labels,omitempty"`
	Description jiraADF     `json:"description"`
}

type jiraProject struct {
	Key string `json:"key"`
}
type jiraName struct {
	Name string `json:"name"`
}
type jiraADF struct {
	Type    string      `json:"type"`
	Version int         `json:"version"`
	Content []jiraBlock `json:"content"`
}
type jiraBlock struct {
	Type    string     `json:"type"`
	Content []jiraText `json:"content"`
}
type jiraText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func NewJira(cfg config.Jira, user, token string) *Jira {
	return &Jira{cfg: cfg, user: user, token: token, client: &http.Client{Timeout: 8 * time.Second}}
}

func (j *Jira) Name() string { return "jira" }

func (j *Jira) Notify(ctx context.Context, sub *domain.Submission) error {
	if sub == nil || sub.Result == nil || sub.Result.Verdict.Rank() < domain.Verdict(j.cfg.MinVerdict).Rank() {
		return nil
	}
	if strings.TrimSpace(j.cfg.APIURL) == "" || strings.TrimSpace(j.cfg.ProjectKey) == "" || strings.TrimSpace(j.cfg.IssueType) == "" || strings.TrimSpace(j.token) == "" {
		return fmt.Errorf("jira: api_url, project_key, issue_type and token are required")
	}
	e := EventFrom(sub)
	description := fmt.Sprintf("verdict=%s score=%d confidence=%.2f signals=%s sender_domain=%s link_domains=%s attachment_sha256=%s submission_id=%s", e.Verdict, e.Score, e.Confidence, strings.Join(e.Signals, ","), e.SenderDomain, strings.Join(e.LinkDomains, ","), strings.Join(e.Hashes, ","), e.ID)
	payload := jiraIssue{Fields: jiraFields{
		Project: jiraProject{Key: j.cfg.ProjectKey}, IssueType: jiraName{Name: j.cfg.IssueType},
		Summary: fmt.Sprintf("PhishLens %s: %s", e.Verdict, e.ID), Labels: []string{"phishlens", strings.ToLower(string(e.Verdict))},
		Description: jiraADF{Type: "doc", Version: 1, Content: []jiraBlock{{Type: "paragraph", Content: []jiraText{{Type: "text", Text: description}}}}},
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("jira: encode: %w", err)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(j.cfg.APIURL), "/")
	if !strings.HasSuffix(endpoint, "/rest/api/3/issue") {
		endpoint += "/rest/api/3/issue"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("jira: request: %w", err)
	}
	if strings.TrimSpace(j.user) != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(j.user+":"+j.token)))
	} else {
		req.Header.Set("Authorization", "Bearer "+j.token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "phishlens-jira/1")
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("jira: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("jira: status %d", resp.StatusCode)
	}
	return nil
}
