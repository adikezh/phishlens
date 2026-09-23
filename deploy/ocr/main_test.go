package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExtractURLs(t *testing.T) {
	got := extractURLs("Нажмите https://evil.example/login. Повтор: https://evil.example/login и http://safe.example/a?q=1!")
	require.Equal(t, []string{"https://evil.example/login", "http://safe.example/a?q=1"}, got)
}

func TestOCRHandlerValidatesAndReturnsTextAndURLs(t *testing.T) {
	s := &server{maxBytes: 100, timeout: time.Second, language: "eng+rus+kaz", run: func(context.Context, []byte, string) (string, error) {
		return "Проверить https://evil.example/login", nil
	}}
	r := httptest.NewRequest(http.MethodPost, "/ocr", strings.NewReader("image"))
	r.Header.Set("Content-Type", "image/png")
	w := httptest.NewRecorder()
	s.ocr(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "https://evil.example/login")

	bad := httptest.NewRequest(http.MethodPost, "/ocr", strings.NewReader("not image"))
	bad.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	s.ocr(w, bad)
	require.Equal(t, http.StatusUnsupportedMediaType, w.Code)
}
