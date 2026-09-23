// Command phishlens-ocr is a small, isolated Tesseract HTTP adapter.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const defaultMaxImageBytes int64 = 25 << 20

var urlPattern = regexp.MustCompile(`https?://[^\s<>"'()]+`)

type ocrResponse struct {
	Text string   `json:"text"`
	URLs []string `json:"urls"`
}

type server struct {
	maxBytes int64
	language string
	timeout  time.Duration
	run      func(context.Context, []byte, string) (string, error)
}

func main() {
	listen := flag.String("listen", ":8090", "HTTP listen address")
	flag.Parse()
	s := &server{maxBytes: envInt64("OCR_MAX_IMAGE_BYTES", defaultMaxImageBytes), language: envOr("OCR_LANG", "eng+rus+kaz"), timeout: envDuration("OCR_TIMEOUT", 15*time.Second), run: runTesseract}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/ocr", s.ocr)
	h := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second}
	if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (s *server) ocr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); !strings.HasPrefix(ct, "image/") {
		writeError(w, http.StatusUnsupportedMediaType, "content_type_must_be_image")
		return
	}
	if r.ContentLength > s.maxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "image_too_large")
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, s.maxBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_image_failed")
		return
	}
	if int64(len(b)) > s.maxBytes || len(b) == 0 {
		writeError(w, http.StatusRequestEntityTooLarge, "image_too_large_or_empty")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()
	text, err := s.run(ctx, b, s.language)
	if err != nil {
		writeError(w, http.StatusBadGateway, "ocr_failed")
		return
	}
	writeJSON(w, http.StatusOK, ocrResponse{Text: text, URLs: extractURLs(text)})
}

func runTesseract(ctx context.Context, image []byte, language string) (string, error) {
	f, err := os.CreateTemp("", "phishlens-ocr-*")
	if err != nil {
		return "", fmt.Errorf("create temp image: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("protect temp image: %w", err)
	}
	if _, err := f.Write(image); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write temp image: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp image: %w", err)
	}
	out, err := exec.CommandContext(ctx, "tesseract", name, "stdout", "-l", language, "--psm", "3").Output()
	if err != nil {
		return "", fmt.Errorf("tesseract: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func extractURLs(text string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range urlPattern.FindAllString(text, -1) {
		raw = strings.TrimRight(raw, ".,;:!?]")
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func envInt64(name string, fallback int64) int64 {
	var value int64
	if _, err := fmt.Sscan(os.Getenv(name), &value); err == nil && value > 0 {
		return value
	}
	return fallback
}
func envDuration(name string, fallback time.Duration) time.Duration {
	if value, err := time.ParseDuration(strings.TrimSpace(os.Getenv(name))); err == nil && value > 0 {
		return value
	}
	return fallback
}
