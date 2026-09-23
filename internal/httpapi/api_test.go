package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *app.App) {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.DSN = "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "api.db"))
	cfg.Analysis.DataDir, cfg.Analysis.BrandsFile, cfg.Analysis.WeightsFile, cfg.Analysis.PromptsDir = "", "", "", ""
	cfg.Server.RateLimitRPS = 0
	a, err := app.New(context.Background(), cfg, zerolog.Nop(), app.Options{Offline: true})
	require.NoError(t, err)
	srv := httptest.NewServer(New(a).Handler(func(chi.Router) {}))
	t.Cleanup(func() { srv.Close(); _ = a.Close() })
	return srv, a
}

func TestAnalyzeJSONAndGet(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"text": "From: \"Kaspi\" <x@kaspi-login.top>\nSubject: Срочно\n\nВведите код из SMS: http://kaspi-login.top/v", "lang": "en"})
	resp, err := http.Post(srv.URL+"/v1/analyze", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out AnalyzeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.ID)
	require.NotNil(t, out.Result)
	require.NotEqual(t, "clean", string(out.Result.Verdict))
	require.Contains(t, out.Result.Signals[0].Explanation, " ", "english explanation rendered")

	r2, err := http.Get(srv.URL + "/v1/analyses/" + out.ID)
	require.NoError(t, err)
	defer r2.Body.Close()
	require.Equal(t, http.StatusOK, r2.StatusCode)

	r3, err := http.Get(srv.URL + "/v1/analyses/01DOESNOTEXIST")
	require.NoError(t, err)
	r3.Body.Close()
	require.Equal(t, http.StatusNotFound, r3.StatusCode)
}

func TestAuthAndRoles(t *testing.T) {
	srv, a := newTestServer(t)
	// analyst endpoints need a key
	r, _ := http.Get(srv.URL + "/v1/submissions")
	r.Body.Close()
	require.Equal(t, http.StatusUnauthorized, r.StatusCode)

	key, _ := GenerateKey()
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{ID: ulid.Make().String(), Name: "t", Role: RoleUser, KeyHash: HashKey(key), CreatedAt: time.Now()}))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/submissions", nil)
	req.Header.Set("X-API-Key", key)
	r, _ = http.DefaultClient.Do(req)
	r.Body.Close()
	require.Equal(t, http.StatusForbidden, r.StatusCode, "user role cannot list submissions")

	req.Header.Set("X-API-Key", "pl_bogus")
	r, _ = http.DefaultClient.Do(req)
	r.Body.Close()
	require.Equal(t, http.StatusUnauthorized, r.StatusCode)

	admin, _ := GenerateKey()
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{ID: ulid.Make().String(), Name: "adm", Role: RoleAdmin, KeyHash: HashKey(admin), CreatedAt: time.Now()}))
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Del("X-API-Key")
	r, _ = http.DefaultClient.Do(req)
	r.Body.Close()
	require.Equal(t, http.StatusOK, r.StatusCode)
}

func TestHealthAndBrands(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, p := range []string{"/health", "/v1/brands", "/v1/signals", "/v1/demos", "/metrics"} {
		r, err := http.Get(srv.URL + p)
		require.NoError(t, err)
		r.Body.Close()
		require.Equal(t, http.StatusOK, r.StatusCode, p)
	}
	r, _ := http.Get(srv.URL + "/v1/webhooks")
	r.Body.Close()
	require.Equal(t, http.StatusUnauthorized, r.StatusCode)
}

func TestAnalystQueueActions(t *testing.T) {
	srv, a := newTestServer(t)
	admin, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{ID: ulid.Make().String(), Name: "analyst", Role: RoleAdmin, KeyHash: HashKey(admin), CreatedAt: time.Now()}))

	body, _ := json.Marshal(map[string]any{"text": "Срочно подтвердите код: https://kaspi-login.top/verify"})
	r, err := http.Post(srv.URL+"/v1/analyze", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	var out AnalyzeResponse
	require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
	r.Body.Close()
	require.Equal(t, http.StatusOK, r.StatusCode)

	request := func(method, path string, body []byte) *http.Response {
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+admin)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	r = request(http.MethodPost, "/v1/submissions/"+out.ID+"/block-domain", []byte(`{"domain":"kaspi-login.top"}`))
	require.Equal(t, http.StatusCreated, r.StatusCode)
	r.Body.Close()
	r = request(http.MethodGet, "/v1/lists/block", nil)
	require.Equal(t, http.StatusOK, r.StatusCode)
	var entries []store.ListEntry
	require.NoError(t, json.NewDecoder(r.Body).Decode(&entries))
	r.Body.Close()
	require.NotEmpty(t, entries)

	r = request(http.MethodPost, "/v1/submissions/"+out.ID+"/incident", []byte(`{}`))
	require.Equal(t, http.StatusCreated, r.StatusCode)
	r.Body.Close()
	r = request(http.MethodGet, "/v1/campaigns", nil)
	require.Equal(t, http.StatusOK, r.StatusCode)
	r.Body.Close()
}

func TestUserCanReportSubmission(t *testing.T) {
	srv, a := newTestServer(t)
	key, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{
		ID: ulid.Make().String(), Name: "employee", Role: RoleUser, OrgID: "org-a", KeyHash: HashKey(key), CreatedAt: time.Now(),
	}))
	body, _ := json.Marshal(map[string]any{"text": "Please review https://example.com", "channel": "outlook"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/analyze", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var out AnalyzeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/submissions/"+out.ID+"/report", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/v1/analyses/"+out.ID, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	var got AnalyzeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, domain.StatusInReview, got.Status)
}

func TestAdminWebhookLifecycle(t *testing.T) {
	t.Setenv("PL_ENC_KEY", strings.Repeat("ab", 32))
	srv, a := newTestServer(t)
	admin, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{ID: ulid.Make().String(), Name: "adm", Role: RoleAdmin, OrgID: "org-a", KeyHash: HashKey(admin), CreatedAt: time.Now()}))

	request := func(method, path string, body string) *http.Response {
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+admin)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	resp := request(http.MethodPost, "/v1/webhooks", `{"name":"soar","url":"https://soar.example.test/phishlens","secret":"0123456789abcdef"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created store.Webhook
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	require.NotEmpty(t, created.ID)
	require.True(t, created.SecretConfigured)
	require.Empty(t, created.Secret)

	resp = request(http.MethodGet, "/v1/webhooks", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listed []store.Webhook
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listed))
	resp.Body.Close()
	require.Len(t, listed, 1)
	require.Empty(t, listed[0].Secret)

	resp = request(http.MethodDelete, "/v1/webhooks/"+created.ID, "")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
	resp = request(http.MethodGet, "/v1/webhooks", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var after []store.Webhook
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&after))
	resp.Body.Close()
	require.Empty(t, after)
}

func TestDetectKind(t *testing.T) {
	k, err := DetectKind("a.eml", "", []byte("From: x"))
	require.NoError(t, err)
	require.Equal(t, "eml", string(k))
	k, _ = DetectKind("shot.PNG", "", nil)
	require.Equal(t, "image", string(k))
	k, _ = DetectKind("m.msg", "", nil)
	require.Equal(t, "msg", string(k))
	k, err = DetectKind("x.pdf", "", nil)
	require.NoError(t, err)
	require.Equal(t, "pdf", string(k))
	k, _ = DetectKind("", "", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0})
	require.Equal(t, "image", string(k))
}
