package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func abuseIPDBLookup(ctx context.Context, client *http.Client, endpoint, ip, key string) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("abuseipdb: API key is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return false, err
	}
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("abuseipdb: HTTP %s", resp.Status)
	}
	var out struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return false, err
	}
	return out.Data.AbuseConfidenceScore >= 50, nil
}
