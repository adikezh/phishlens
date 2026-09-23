package reputation

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const openPhishFeedURL = "https://openphish.com/feed.txt"

var openPhishFeedCache struct {
	sync.Mutex
	hosts   map[string]struct{}
	expires time.Time
}

func openphishLookup(ctx context.Context, domain string) (bool, error) {
	want := canonicalHost(domain)
	if want == "" {
		return false, nil
	}
	openPhishFeedCache.Lock()
	defer openPhishFeedCache.Unlock()
	if time.Now().Before(openPhishFeedCache.expires) {
		_, ok := openPhishFeedCache.hosts[want]
		return ok, nil
	}
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
	hosts, err := openPhishFeedSet(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return false, err
	}
	openPhishFeedCache.hosts = hosts
	openPhishFeedCache.expires = time.Now().Add(12 * time.Hour)
	_, ok := hosts[want]
	return ok, nil
}

func openPhishFeedContains(r io.Reader, domain string) (bool, error) {
	hosts, err := openPhishFeedSet(r)
	if err != nil {
		return false, err
	}
	_, ok := hosts[canonicalHost(domain)]
	return ok, nil
}

func openPhishFeedSet(r io.Reader) (map[string]struct{}, error) {
	hosts := make(map[string]struct{})
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
		if host := canonicalHost(u.Hostname()); host != "" {
			hosts[host] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("openphish: feed: %w", err)
	}
	return hosts, nil
}

func canonicalHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
