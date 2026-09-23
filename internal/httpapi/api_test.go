package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
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

func TestAnalyzeReturns202ForSlowJob(t *testing.T) {
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"test","message":{"content":"{\"verdict_opinion\":\"suspicious\",\"attack_type\":\"none\",\"summary\":\"review\",\"social_engineering_tactics\":[],\"recommended_action\":\"review\",\"questions_for_analyst\":[]}"}}`)
	}))
	defer llmServer.Close()
	cfg := config.Default()
	cfg.Storage.DSN = "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "slow.db"))
	cfg.Analysis.DataDir, cfg.Analysis.BrandsFile, cfg.Analysis.WeightsFile, cfg.Analysis.PromptsDir = "", "", "", ""
	cfg.Server.RateLimitRPS = 0
	cfg.Analysis.Timeout = time.Second
	cfg.LLM.Enabled = true
	cfg.LLM.Timeout = time.Second
	cfg.LLM.Providers = []config.LLMProvider{{Name: "slow", Type: "ollama", BaseURL: llmServer.URL, Model: "test"}}
	a, err := app.New(context.Background(), cfg, zerolog.Nop(), app.Options{Offline: true})
	require.NoError(t, err)
	defer a.Close()
	api := New(a)
	api.syncBudget = 10 * time.Millisecond
	srv := httptest.NewServer(api.Handler(func(chi.Router) {}))
	defer srv.Close()

	body := strings.NewReader(`{"text":"Please review https://example.test"}`)
	resp, err := http.Post(srv.URL+"/v1/analyze", "application/json", body)
	require.NoError(t, err)
	var pending AnalyzeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pending))
	resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Equal(t, "/v1/analyses/"+pending.ID, resp.Header.Get("Location"))
	require.Equal(t, domain.StatusProcessing, pending.Status)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := http.Get(srv.URL + "/v1/analyses/" + pending.ID)
		if err == nil {
			var out AnalyzeResponse
			_ = json.NewDecoder(got.Body).Decode(&out)
			got.Body.Close()
			if got.StatusCode == http.StatusOK && out.Result != nil {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("slow analysis did not complete through polling resource")
}

func TestMultipartPersistenceAndAnalystDeletion(t *testing.T) {
	srv, a := newTestServer(t)
	admin, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{ID: ulid.Make().String(), Name: "admin", Role: RoleAdmin, KeyHash: HashKey(admin), CreatedAt: time.Now()}))

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="notice.eml"`)
	h.Set("Content-Type", "message/rfc822")
	part, err := mw.CreatePart(h)
	require.NoError(t, err)
	_, err = io.WriteString(part, "From: sender@example.test\r\nSubject: Notice\r\n\r\nPlease review https://example.test")
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/analyze", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var out AnalyzeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, out.ID)

	req, err = http.NewRequest(http.MethodDelete, srv.URL+"/v1/submissions/"+out.ID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	req, err = http.NewRequest(http.MethodGet, srv.URL+"/v1/analyses/"+out.ID, nil)
	require.NoError(t, err)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
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

func TestSubmissionMutationsAreOrgScoped(t *testing.T) {
	srv, a := newTestServer(t)
	newKey := func(name, org string) string {
		key, err := GenerateKey()
		require.NoError(t, err)
		require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{
			ID: ulid.Make().String(), Name: name, Role: RoleAdmin, OrgID: org, KeyHash: HashKey(key), CreatedAt: time.Now(),
		}))
		return key
	}
	orgA, orgB := newKey("org-a-admin", "org-a"), newKey("org-b-admin", "org-b")

	body, err := json.Marshal(map[string]any{"text": "Please review https://example.com", "channel": "outlook"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/analyze", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+orgA)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var out AnalyzeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mutate := func(method string) int {
		req, err := http.NewRequest(method, srv.URL+"/v1/submissions/"+out.ID, strings.NewReader(`{"status":"confirmed_phish"}`))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+orgB)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	require.Equal(t, http.StatusNotFound, mutate(http.MethodPatch))
	require.Equal(t, http.StatusNotFound, mutate(http.MethodDelete))
}

func TestAdminCanExportSubjectDataWithinOrg(t *testing.T) {
	srv, a := newTestServer(t)
	admin, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, a.Store.CreateAPIKey(context.Background(), store.APIKey{
		ID: ulid.Make().String(), Name: "admin", Role: RoleAdmin, OrgID: "org-a", KeyHash: HashKey(admin), CreatedAt: time.Now(),
	}))

	submit := func(subject string) string {
		body, err := json.Marshal(map[string]any{
			"text":         "From: sender@example.test\nSubject: Notice\n\nPlease review https://example.test",
			"submitted_by": subject,
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/analyze", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out AnalyzeResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return out.ID
	}

	submit("person@example.test")
	submit("other@example.test")
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/privacy/export?subject=PERSON%40EXAMPLE.TEST", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Content-Disposition"), "phishlens-subject-export.json")
	var export SubjectExport
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&export))
	require.Equal(t, "PERSON@EXAMPLE.TEST", export.Subject)
	require.Len(t, export.Submissions, 1)
	require.Equal(t, "person@example.test", export.Submissions[0].SubmittedBy)
	if export.Submissions[0].Message != nil {
		require.Empty(t, export.Submissions[0].Message.TextBody, "Community export must not include an unencrypted body")
		require.Empty(t, export.Submissions[0].Message.HTMLBody, "Community export must not include an unencrypted body")
	}
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
