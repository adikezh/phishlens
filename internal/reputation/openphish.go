package reputation

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const openPhishFeedURL = "https://openphish.com/feed.txt"

func openphishLookup(ctx context.Context, domain string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openPhishFeedURL, nil)
	if err != nil {
		return false, err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("openphish: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("openphish: http %s", resp.Status)
	}
	return openPhishFeedContains(io.LimitReader(resp.Body, 32<<20), domain)
}

func openPhishFeedContains(r io.Reader, domain string) (bool, error) {
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), want) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("openphish: feed: %w", err)
	}
	return false, nil
}
