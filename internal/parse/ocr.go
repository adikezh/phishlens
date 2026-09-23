package parse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TesseractOCR calls the optional phishlens-ocr container (deploy/ocr):
// POST {url}/ocr  multipart/octet-stream → {"text": "...", "urls": [...]}.
type TesseractOCR struct {
	URL    string
	Client *http.Client
}

// NewTesseractOCR returns a client with a sane timeout.
func NewTesseractOCR(url string) *TesseractOCR {
	return &TesseractOCR{URL: url, Client: &http.Client{Timeout: 20 * time.Second}}
}

// Extract implements OCR.
func (t *TesseractOCR) Extract(ctx context.Context, img []byte, mime string) (string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL+"/ocr", bytes.NewReader(img))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", mime)
	resp, err := t.Client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("ocr: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", nil, fmt.Errorf("ocr: status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Text string   `json:"text"`
		URLs []string `json:"urls"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("ocr: decode: %w", err)
	}
	return out.Text, append(out.URLs, ExtractURLs(out.Text)...), nil
}

// TODO(F-4.1.9): VisionOCR — llm.Provider with vision model + prompts/vision_extract_v1.txt.
