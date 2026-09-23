package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/phishlens/phishlens/internal/domain"
)

// Webhook POSTs the Event as JSON with an HMAC-SHA256 signature (F-4.9.2):
//
//	X-PhishLens-Timestamp: <unix>
//	X-PhishLens-Signature: sha256=<hex hmac(secret, timestamp + "." + body)>
type Webhook struct {
	URL    string
	secret []byte
	Client *http.Client
}

// NewWebhook builds a signed webhook sender.
func NewWebhook(url, secret string) *Webhook {
	return &Webhook{URL: url, secret: []byte(secret), Client: &http.Client{Timeout: 8 * time.Second}}
}

func (w *Webhook) Name() string { return "webhook" }

// Sign computes the signature for a timestamp/body pair (exported for receivers/tests).
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Notify implements Notifier.
func (w *Webhook) Notify(ctx context.Context, sub *domain.Submission) error {
	body, err := json.Marshal(EventFrom(sub))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "phishlens-webhook/1")
	req.Header.Set("X-PhishLens-Timestamp", ts)
	if len(w.secret) > 0 {
		req.Header.Set("X-PhishLens-Signature", Sign(w.secret, ts, body))
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: status %d", resp.StatusCode)
	}
	return nil
}
