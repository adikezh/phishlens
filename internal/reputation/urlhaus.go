package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const urlhausHostEndpoint = "https://urlhaus-api.abuse.ch/v1/host/"

func urlhausLookup(ctx context.Context, domain, authKey string) (bool, error) {
	if strings.TrimSpace(authKey) == "" {
		return false, fmt.Errorf("urlhaus: auth key is not configured")
	}
	form := url.Values{"host": {domain}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlhausHostEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", authKey)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("urlhaus: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("urlhaus: http %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return false, fmt.Errorf("urlhaus: read: %w", err)
	}
	return parseURLhausResponse(body)
}

func parseURLhausResponse(body []byte) (bool, error) {
	var response struct {
		QueryStatus string            `json:"query_status"`
		URLs        []json.RawMessage `json:"urls"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("urlhaus: decode: %w", err)
	}
	if response.QueryStatus == "no_results" {
		return false, nil
	}
	if response.QueryStatus != "ok" {
		return false, fmt.Errorf("urlhaus: query status %q", response.QueryStatus)
	}
	return len(response.URLs) > 0, nil
}
