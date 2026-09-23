// Package graph implements the Microsoft Graph mailbox receiver (F-4.1.5)
// using application permissions and the messages delta endpoint.
package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

const maxMessageBytes = 25 << 20

// AnalyzeFunc is the application boundary used by the receiver.
type AnalyzeFunc func(context.Context, app.Request) (*domain.Submission, error)

// Receiver polls the mailbox delta feed and analyzes new messages.
type Receiver struct {
	cfg     config.Graph
	analyze AnalyzeFunc
	client  *http.Client
	baseURL string
}

// New builds a receiver.
func New(cfg config.Graph, analyze ...AnalyzeFunc) *Receiver {
	var fn AnalyzeFunc
	if len(analyze) > 0 {
		fn = analyze[0]
	}
	return &Receiver{cfg: cfg, analyze: fn, client: &http.Client{Timeout: 35 * time.Second}, baseURL: "https://graph.microsoft.com/v1.0"}
}

func (r *Receiver) Name() string { return "graph" }

type deltaPage struct {
	Value     []deltaMessage `json:"value"`
	NextLink  string         `json:"@odata.nextLink"`
	DeltaLink string         `json:"@odata.deltaLink"`
}

type deltaMessage struct {
	ID      string          `json:"id"`
	Removed json.RawMessage `json:"@removed,omitempty"`
}

func (r *Receiver) Run(ctx context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	if r.cfg.TenantID == "" || r.cfg.ClientID == "" || r.cfg.Mailbox == "" {
		return errors.New("graph: tenant_id, client_id and mailbox are required")
	}
	if r.analyze == nil {
		return errors.New("graph: analyzer is not configured")
	}
	secret := os.Getenv(r.cfg.ClientSecretEnv)
	if secret == "" {
		return errors.New("graph: client secret environment variable is empty")
	}
	interval := r.cfg.PollInterval
	if interval <= 0 {
		interval = time.Minute
	}
	var deltaURL string
	if r.cfg.StateFile != "" {
		if b, err := os.ReadFile(r.cfg.StateFile); err == nil {
			deltaURL = strings.TrimSpace(string(b))
		}
	}
	for {
		var err error
		deltaURL, err = r.poll(ctx, secret, deltaURL)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		if r.cfg.StateFile != "" && deltaURL != "" {
			if err := saveState(r.cfg.StateFile, deltaURL); err != nil {
				return fmt.Errorf("graph: save delta state: %w", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (r *Receiver) poll(ctx context.Context, secret, current string) (string, error) {
	conf := clientcredentials.Config{
		ClientID:     r.cfg.ClientID,
		ClientSecret: secret,
		TokenURL:     "https://login.microsoftonline.com/" + url.PathEscape(r.cfg.TenantID) + "/oauth2/v2.0/token",
		EndpointParams: url.Values{
			"scope": {"https://graph.microsoft.com/.default"},
		},
	}
	token, err := conf.Token(ctx)
	if err != nil {
		return current, fmt.Errorf("graph: token: %w", err)
	}
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	endpoint := current
	if endpoint == "" {
		endpoint = r.baseURL + "/users/" + url.PathEscape(r.cfg.Mailbox) + "/mailFolders/inbox/messages/delta?$select=id"
	}
	for endpoint != "" {
		var page deltaPage
		if err := r.requestJSON(ctx, client, http.MethodGet, endpoint, nil, &page); err != nil {
			return current, err
		}
		for _, item := range page.Value {
			if item.ID == "" || len(item.Removed) > 0 {
				continue
			}
			raw, err := r.fetchMIME(ctx, client, item.ID)
			if err != nil {
				return current, err
			}
			if _, err := r.analyze(ctx, app.Request{Channel: domain.ChannelIMAP, Kind: domain.KindEML, Data: raw, OrgID: r.cfg.OrgID}); err != nil {
				return current, fmt.Errorf("graph: analyze %s: %w", item.ID, err)
			}
			if err := r.markRead(ctx, client, item.ID); err != nil {
				return current, err
			}
		}
		if page.NextLink != "" {
			endpoint = page.NextLink
			continue
		}
		if page.DeltaLink != "" {
			return page.DeltaLink, nil
		}
		return current, nil
	}
	return current, nil
}

func (r *Receiver) fetchMIME(ctx context.Context, client *http.Client, id string) ([]byte, error) {
	endpoint := r.baseURL + "/users/" + url.PathEscape(r.cfg.Mailbox) + "/messages/" + url.PathEscape(id) + "/$value"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graph: fetch MIME: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("graph: fetch MIME: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMessageBytes {
		return nil, errors.New("graph: MIME message exceeds 25 MiB")
	}
	return b, nil
}

func (r *Receiver) markRead(ctx context.Context, client *http.Client, id string) error {
	body := []byte(`{"isRead":true}`)
	endpoint := r.baseURL + "/users/" + url.PathEscape(r.cfg.Mailbox) + "/messages/" + url.PathEscape(id)
	return r.requestJSON(ctx, client, http.MethodPatch, endpoint, body, nil)
}

func (r *Receiver) requestJSON(ctx context.Context, client *http.Client, method, endpoint string, body []byte, out any) error {
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("graph: %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("graph: %s: status %d", method, resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("graph: %s decode: %w", method, err)
		}
	}
	return nil
}

func saveState(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
