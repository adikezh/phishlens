package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func isSHA256(s string) bool { return sha256Pattern.MatchString(s) }

func virusTotalLookup(ctx context.Context, client *http.Client, endpoint, sha256, key string) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("virustotal: API key is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/"+sha256, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-apikey", key)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return false, nil
	}
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("virustotal: HTTP %s", resp.Status)
	}
	var out struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		return false, err
	}
	return out.Data.Attributes.LastAnalysisStats.Malicious > 0 || out.Data.Attributes.LastAnalysisStats.Suspicious > 0, nil
}
