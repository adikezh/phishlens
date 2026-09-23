package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/review"
	"github.com/phishlens/phishlens/internal/store"
)

// analyzeJSON is the JSON body of POST /v1/analyze (F-4.1.2).
type analyzeJSON struct {
	Text        string `json:"text"`
	EMLBase64   string `json:"eml_base64"`
	ImageBase64 string `json:"image_base64"`
	Lang        string `json:"lang"`
	NoLLM       bool   `json:"no_llm"`
	SubmittedBy string `json:"submitted_by"`
	Channel     string `json:"channel"`
}

// AnalyzeResponse is returned by POST /v1/analyze and GET /v1/analyses/{id}.
type AnalyzeResponse struct {
	ID         string           `json:"id"`
	Status     domain.Status    `json:"status"`
	Channel    domain.Channel   `json:"channel"`
	Kind       domain.Kind      `json:"kind"`
	ReceivedAt time.Time        `json:"received_at"`
	Message    *MessageSummary  `json:"message,omitempty"`
	Result     *domain.Analysis `json:"result,omitempty"`
}

// MessageSummary is the privacy-safe projection of ParsedMail.
type MessageSummary struct {
	From        string              `json:"from,omitempty"`
	ReplyTo     string              `json:"reply_to,omitempty"`
	Subject     string              `json:"subject,omitempty"`
	Date        string              `json:"date,omitempty"`
	Language    string              `json:"language,omitempty"`
	Links       []domain.Link       `json:"links,omitempty"`
	Attachments []domain.Attachment `json:"attachments,omitempty"`
	AuthResults domain.AuthResults  `json:"auth_results"`
	PDF         *domain.PDFInfo     `json:"pdf,omitempty"`
}

func toResponse(sub *domain.Submission) AnalyzeResponse {
	resp := AnalyzeResponse{ID: sub.ID, Status: sub.Status, Channel: sub.Channel, Kind: sub.Kind, ReceivedAt: sub.ReceivedAt, Result: sub.Result}
	if m := sub.Message; m != nil {
		ms := &MessageSummary{From: m.From.String(), ReplyTo: m.ReplyTo.String(), Subject: m.Subject, Language: m.Language,
			Links: m.Links, Attachments: m.Attachments, AuthResults: m.AuthResults, PDF: m.PDF}
		if !m.Date.IsZero() {
			ms.Date = m.Date.Format(time.RFC3339)
		}
		resp.Message = ms
	}
	return resp
}

// DetectKind picks the input kind from a filename / content type / sniffing.
func DetectKind(filename, contentType string, data []byte) (domain.Kind, error) {
	ext := strings.ToLower(path.Ext(filename))
	ct := strings.ToLower(contentType)
	switch {
	case ext == ".eml" || strings.Contains(ct, "message/rfc822"):
		return domain.KindEML, nil
	case ext == ".msg" || strings.Contains(ct, "vnd.ms-outlook"):
		return domain.KindMSG, nil
	case ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || strings.HasPrefix(ct, "image/"):
		return domain.KindImage, nil
	case ext == ".pdf" || strings.Contains(ct, "application/pdf"):
		return domain.KindPDF, nil
	case ext == ".txt" || strings.HasPrefix(ct, "text/"):
		return domain.KindText, nil
	}
	sniff := http.DetectContentType(data)
	switch {
	case strings.HasPrefix(sniff, "image/"):
		return domain.KindImage, nil
	case len(data) >= 8 && data[0] == 0xD0 && data[1] == 0xCF:
		return domain.KindMSG, nil
	default:
		return domain.KindEML, nil
	}
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	maxBytes := int64(s.app.Cfg.Server.MaxUploadMB) << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+4096)
	p := PrincipalFrom(r.Context())
	req := app.Request{Channel: domain.ChannelAPI, OrgID: p.OrgID}

	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(ct, "multipart/"):
		if err := r.ParseMultipartForm(maxBytes); err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
			return
		}
		req.Lang = r.FormValue("lang")
		req.NoLLM = r.FormValue("no_llm") == "true" || r.FormValue("no_llm") == "1"
		req.SubmittedBy = r.FormValue("submitted_by")
		if ch := r.FormValue("channel"); ch != "" {
			req.Channel = domain.Channel(ch)
		}
		if f, hdr, err := r.FormFile("file"); err == nil {
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
			if err != nil || int64(len(data)) > maxBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "too_large", "file exceeds max_upload_mb")
				return
			}
			kind, err := DetectKind(hdr.Filename, hdr.Header.Get("Content-Type"), data)
			if err != nil {
				writeError(w, http.StatusUnsupportedMediaType, "unsupported", err.Error())
				return
			}
			req.Kind, req.Data = kind, data
		} else if t := r.FormValue("text"); strings.TrimSpace(t) != "" {
			req.Kind, req.Data = domain.KindText, []byte(t)
		} else if d := r.FormValue("demo"); d != "" {
			b, ok := app.DemoBytes(d)
			if !ok {
				writeError(w, http.StatusNotFound, "not_found", "unknown demo")
				return
			}
			req.Kind, req.Data = domain.KindEML, b
		}
	default:
		var body analyzeJSON
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
			return
		}
		req.Lang, req.NoLLM, req.SubmittedBy = body.Lang, body.NoLLM, body.SubmittedBy
		if body.Channel != "" {
			req.Channel = domain.Channel(body.Channel)
		}
		switch {
		case body.EMLBase64 != "":
			data, err := base64.StdEncoding.DecodeString(body.EMLBase64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "eml_base64 is not valid base64")
				return
			}
			req.Kind, req.Data = domain.KindEML, data
		case body.ImageBase64 != "":
			data, err := base64.StdEncoding.DecodeString(body.ImageBase64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "image_base64 is not valid base64")
				return
			}
			req.Kind, req.Data = domain.KindImage, data
		case strings.TrimSpace(body.Text) != "":
			req.Kind, req.Data = domain.KindText, []byte(body.Text)
		}
	}
	if len(req.Data) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "provide text, eml_base64, image_base64 or a multipart file")
		return
	}
	sub, err := s.app.Analyzer.Analyze(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, parse.ErrNotImplemented):
			writeError(w, http.StatusNotImplemented, "not_implemented", err.Error())
		case errors.Is(err, parse.ErrTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
		case errors.Is(err, parse.ErrEmpty):
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		default:
			writeError(w, http.StatusUnprocessableEntity, "parse_error", err.Error())
		}
		return
	}
	// TODO(F-4.1.2): if analysis exceeds the sync budget return 202 + Location: /v1/analyses/{id}.
	writeJSON(w, http.StatusOK, toResponse(sub))
}

func (s *Server) handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "storage disabled")
		return
	}
	sub, err := s.app.Store.GetSubmission(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "analysis not found")
			return
		}
		s.log.Error().Err(err).Msg("get submission")
		writeError(w, http.StatusInternalServerError, "internal", "storage error")
		return
	}
	p := PrincipalFrom(r.Context())
	if p.OrgID != "" && sub.OrgID != p.OrgID {
		writeError(w, http.StatusNotFound, "not_found", "analysis not found")
		return
	}
	writeJSON(w, http.StatusOK, toResponse(sub))
}

func (s *Server) handleListSubmissions(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	q := r.URL.Query()
	f := store.SubmissionFilter{OrgID: PrincipalFrom(r.Context()).OrgID, Verdict: domain.Verdict(q.Get("verdict")), Status: domain.Status(q.Get("status"))}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if since := q.Get("since"); since != "" {
		if d, err := config.ParseDuration(since); err == nil {
			f.Since = time.Now().Add(-d)
		}
	}
	subs, err := s.app.Store.ListSubmissions(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]AnalyzeResponse, 0, len(subs))
	for _, sub := range subs {
		out = append(out, toResponse(sub))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "storage disabled")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	st := domain.Status(body.Status)
	switch st {
	case domain.StatusInReview, domain.StatusConfirmedPhish, domain.StatusConfirmedClean, domain.StatusEscalated:
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "invalid status")
		return
	}
	p := PrincipalFrom(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.app.Store.UpdateSubmissionStatus(r.Context(), id, st, p.Name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "submission not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "submission.review", Target: id, Details: body.Status})
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": body.Status})
}

// handleReportSubmission lets a regular employee move their own analyzed item
// into the analyst queue without granting them review or list-management power.
func (s *Server) handleReportSubmission(w http.ResponseWriter, r *http.Request) {
	sub, p, ok := s.submissionForActor(w, r)
	if !ok {
		return
	}
	if sub.Status == domain.StatusConfirmedPhish || sub.Status == domain.StatusConfirmedClean {
		writeError(w, http.StatusConflict, "already_reviewed", "submission already has an analyst decision")
		return
	}
	if err := s.app.Store.UpdateSubmissionStatus(r.Context(), sub.ID, domain.StatusInReview, p.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "submission.report", Target: sub.ID})
	writeJSON(w, http.StatusAccepted, map[string]string{"id": sub.ID, "status": string(domain.StatusInReview)})
}

func (s *Server) submissionForActor(w http.ResponseWriter, r *http.Request) (*domain.Submission, Principal, bool) {
	if s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "storage disabled")
		return nil, Principal{}, false
	}
	p := PrincipalFrom(r.Context())
	sub, err := s.app.Store.GetSubmission(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && p.OrgID != "" && sub.OrgID != p.OrgID) {
		writeError(w, http.StatusNotFound, "not_found", "submission not found")
		return nil, Principal{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "storage error")
		return nil, Principal{}, false
	}
	return sub, p, true
}

func (s *Server) handleBlockDomain(w http.ResponseWriter, r *http.Request) {
	sub, p, ok := s.submissionForActor(w, r)
	if !ok {
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	domainName := strings.ToLower(strings.TrimSpace(body.Domain))
	if domainName == "" && sub.Message != nil {
		if len(sub.Message.Links) > 0 {
			domainName = strings.ToLower(strings.TrimSpace(sub.Message.Links[0].Domain))
		}
		if domainName == "" {
			domainName = strings.ToLower(strings.TrimSpace(sub.Message.From.Domain))
		}
	}
	if domainName == "" || net.ParseIP(domainName) != nil || strings.ContainsAny(domainName, "/ @:") {
		writeError(w, http.StatusBadRequest, "bad_request", "a domain is required")
		return
	}
	if err := s.app.Store.AddEntry(r.Context(), store.ListEntry{OrgID: p.OrgID, Kind: store.ListBlock, Value: domainName, CreatedBy: p.Name, Note: "from submission " + sub.ID}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	app.InvalidateListCache()
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "domain.block", Target: domainName, Details: sub.ID})
	writeJSON(w, http.StatusCreated, map[string]string{"domain": domainName, "submission_id": sub.ID})
}

func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	sub, p, ok := s.submissionForActor(w, r)
	if !ok {
		return
	}
	if err := s.app.Store.UpdateSubmissionStatus(r.Context(), sub.ID, domain.StatusEscalated, p.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "incident.create", Target: sub.ID})
	writeJSON(w, http.StatusCreated, map[string]string{"submission_id": sub.ID, "status": string(domain.StatusEscalated)})
}

func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeJSON(w, http.StatusOK, []review.Campaign{})
		return
	}
	q := r.URL.Query()
	f := store.SubmissionFilter{OrgID: PrincipalFrom(r.Context()).OrgID, Verdict: domain.Verdict(q.Get("verdict")), Status: domain.Status(q.Get("status"))}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	subs, err := review.NewQueue(s.app.Store).List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, review.Campaigns(subs))
}

func (s *Server) handleDeleteSubmission(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "storage disabled")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.Store.DeleteSubmission(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "submission not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	p := PrincipalFrom(r.Context())
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "submission.delete", Target: id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListBrands(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Brands.Brands())
}

func (s *Server) handleAddBrand(w http.ResponseWriter, r *http.Request) {
	if !s.app.Cfg.Analysis.CustomBrandsEnabled {
		writeError(w, http.StatusForbidden, "forbidden", "custom brands disabled")
		return
	}
	var b brands.Brand
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.Name) == "" || len(b.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "name and domains are required")
		return
	}
	p := PrincipalFrom(r.Context())
	b.OrgID = p.OrgID
	if s.app.Store != nil {
		if err := s.app.Store.AddBrand(r.Context(), b); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "brand.add", Target: b.Name})
	}
	s.app.Brands.Add(b)
	writeJSON(w, http.StatusCreated, b)
}

func listKind(r *http.Request) (store.ListKind, bool) {
	switch chi.URLParam(r, "kind") {
	case "allow":
		return store.ListAllow, true
	case "block":
		return store.ListBlock, true
	}
	return "", false
}

func (s *Server) handleListEntries(w http.ResponseWriter, r *http.Request) {
	kind, ok := listKind(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "list kind must be allow or block")
		return
	}
	if s.app.Store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	entries, err := s.app.Store.ListEntries(r.Context(), PrincipalFrom(r.Context()).OrgID, kind)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if entries == nil {
		entries = []store.ListEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleAddEntry(w http.ResponseWriter, r *http.Request) {
	kind, ok := listKind(r)
	if !ok || s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "list unavailable")
		return
	}
	var body struct {
		Value string `json:"value"`
		Note  string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Value) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "value is required")
		return
	}
	p := PrincipalFrom(r.Context())
	e := store.ListEntry{OrgID: p.OrgID, Kind: kind, Value: body.Value, Note: body.Note, CreatedBy: p.Name}
	if err := s.app.Store.AddEntry(r.Context(), e); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	app.InvalidateListCache()
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "list.add", Target: string(kind) + ":" + body.Value})
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) handleRemoveEntry(w http.ResponseWriter, r *http.Request) {
	kind, ok := listKind(r)
	if !ok || s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "list unavailable")
		return
	}
	p := PrincipalFrom(r.Context())
	value := chi.URLParam(r, "value")
	if err := s.app.Store.RemoveEntry(r.Context(), p.OrgID, kind, value); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	app.InvalidateListCache()
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "list.remove", Target: string(kind) + ":" + value})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "storage disabled")
		return
	}
	since := time.Now().Add(-30 * 24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := config.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	st, err := s.app.Store.Stats(r.Context(), PrincipalFrom(r.Context()).OrgID, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleDemos(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, app.Demos())
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeJSON(w, http.StatusOK, []store.Webhook{})
		return
	}
	webhooks, err := s.app.Store.ListWebhooks(r.Context(), PrincipalFrom(r.Context()).OrgID)
	if err != nil {
		s.log.Error().Err(err).Msg("list webhooks")
		writeError(w, http.StatusInternalServerError, "internal", "webhook storage error")
		return
	}
	if webhooks == nil {
		webhooks = []store.Webhook{}
	}
	writeJSON(w, http.StatusOK, webhooks)
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "storage_unavailable", "webhooks require storage")
		return
	}
	var body struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Secret  string `json:"secret"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	body.Name, body.URL, body.Secret = strings.TrimSpace(body.Name), strings.TrimSpace(body.URL), strings.TrimSpace(body.Secret)
	if body.Name == "" || len(body.Name) > 128 || !validWebhookURL(body.URL) {
		writeError(w, http.StatusBadRequest, "bad_request", "name and an https webhook URL are required")
		return
	}
	if len([]byte(body.Secret)) < 16 || len([]byte(body.Secret)) > 4096 {
		writeError(w, http.StatusBadRequest, "bad_request", "secret must be 16..4096 bytes")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	p := PrincipalFrom(r.Context())
	webhook := store.Webhook{ID: ulid.Make().String(), OrgID: p.OrgID, Name: body.Name, URL: body.URL, Secret: body.Secret, Enabled: enabled, CreatedAt: time.Now().UTC()}
	if err := s.app.Store.CreateWebhook(r.Context(), webhook); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "conflict", "webhook name already exists")
			return
		}
		s.log.Error().Err(err).Msg("create webhook")
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	webhook.Secret = ""
	webhook.SecretConfigured = true
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "webhook.create", Target: webhook.ID, Details: webhook.Name})
	writeJSON(w, http.StatusCreated, webhook)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	if s.app.Store == nil {
		writeError(w, http.StatusNotFound, "not_found", "storage disabled")
		return
	}
	p := PrincipalFrom(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.app.Store.DeleteWebhook(r.Context(), p.OrgID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "webhook not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.app.Store.Audit(r.Context(), store.AuditEntry{OrgID: p.OrgID, Actor: p.Name, Action: "webhook.delete", Target: id})
	w.WriteHeader(http.StatusNoContent)
}

func validWebhookURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		return host == "localhost" || net.ParseIP(host).IsLoopback()
	}
	return false
}

// handleSignals lists registered checks with their configured weights (signals reference).
func (s *Server) handleSignals(w http.ResponseWriter, _ *http.Request) {
	type sig struct {
		ID       string `json:"id"`
		Category string `json:"category"`
		Weight   int    `json:"weight,omitempty"`
	}
	weights := s.app.Score.Weights().Signals
	var out []sig
	for _, c := range s.app.Registry.Checks() {
		out = append(out, sig{ID: c.ID(), Category: string(c.Category()), Weight: weights[c.ID()]})
	}
	writeJSON(w, http.StatusOK, out)
}
