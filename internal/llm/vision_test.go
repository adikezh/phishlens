package llm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phishlens/phishlens/internal/parse"
	"github.com/stretchr/testify/require"
)

func TestOllamaVisionUsesVisionModelAndImage(t *testing.T) {
	var requestModel string
	var requestImage string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Images []string `json:"images"`
			} `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Messages) != 1 || len(body.Messages[0].Images) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestModel, requestImage = body.Model, body.Messages[0].Images[0]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"llava","message":{"content":"Visible https://example.test"}}`))
	}))
	defer server.Close()
	p := NewOllama("ollama", server.URL, "text", "llava", 0)
	resp, err := p.Vision(context.Background(), []byte("png"), "image/png", "transcribe")
	require.NoError(t, err)
	require.Equal(t, "llava", requestModel)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("png")), requestImage)
	require.Equal(t, "Visible https://example.test", resp.Text)
}

func TestVisionOCRExtractsURLs(t *testing.T) {
	o := parse.NewVisionOCR(func(_ context.Context, _ []byte, _ string) (string, error) {
		return "Кнопка: https://example.test/login", nil
	})
	text, urls, err := o.Extract(context.Background(), []byte("image"), "image/png")
	require.NoError(t, err)
	require.Contains(t, text, "Кнопка")
	require.Len(t, urls, 1)
}
