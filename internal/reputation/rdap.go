package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const rdapEndpoint = "https://rdap.org/domain/"

func rdapAge(ctx context.Context, domain string) (time.Duration, error) {
	if domain == "" || strings.ContainsAny(domain, "/?#") {
		return 0, fmt.Errorf("rdap: invalid domain %q", domain)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapEndpoint+url.PathEscape(strings.ToLower(domain)), nil)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("rdap: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("rdap: http %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return 0, fmt.Errorf("rdap: read: %w", err)
	}
	return parseRDAPAge(body, time.Now().UTC())
}

func parseRDAPAge(body []byte, now time.Time) (time.Duration, error) {
	var doc struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &doc); err != nil {
		return 0, fmt.Errorf("rdap: decode: %w", err)
	}
	for _, event := range doc.Events {
		if strings.EqualFold(event.Action, "registration") {
			registered, err := time.Parse(time.RFC3339, event.Date)
			if err != nil {
				return 0, fmt.Errorf("rdap: registration date: %w", err)
			}
			if registered.After(now) {
				return 0, fmt.Errorf("rdap: registration date is in the future")
			}
			return now.Sub(registered), nil
		}
	}
	return 0, fmt.Errorf("rdap: registration event not found")
}
