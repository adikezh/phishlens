package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type safeBrowsingRequest struct {
	Client struct {
		ClientID      string `json:"clientId"`
		ClientVersion string `json:"clientVersion"`
	} `json:"client"`
	ThreatInfo struct {
		ThreatTypes      []string `json:"threatTypes"`
		PlatformTypes    []string `json:"platformTypes"`
		ThreatEntryTypes []string `json:"threatEntryTypes"`
		ThreatEntries    []struct {
			URL string `json:"url"`
		} `json:"threatEntries"`
	} `json:"threatInfo"`
}
type safeBrowsingResponse struct {
	Matches []json.RawMessage `json:"matches"`
}

func safeBrowsingLookup(ctx context.Context, client *http.Client, endpoint, host, key string) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("safebrowsing: API key is not configured")
	}
	u, err := url.Parse("https://" + host + "/")
	if err != nil || u.Host == "" {
		return false, fmt.Errorf("safebrowsing: invalid host %q", host)
	}
	var req safeBrowsingRequest
	req.Client.ClientID, req.Client.ClientVersion = "phishlens", "1"
	req.ThreatInfo.ThreatTypes = []string{"MALWARE", "SOCIAL_ENGINEERING"}
	req.ThreatInfo.PlatformTypes = []string{"ANY_PLATFORM"}
	req.ThreatInfo.ThreatEntryTypes = []string{"URL"}
	req.ThreatInfo.ThreatEntries = []struct {
		URL string `json:"url"`
	}{{URL: u.String()}}
	body, _ := json.Marshal(req)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"?key="+url.QueryEscape(key), bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("safebrowsing: HTTP %s", resp.Status)
	}
	var out safeBrowsingResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return false, err
	}
	return len(out.Matches) > 0, nil
}
