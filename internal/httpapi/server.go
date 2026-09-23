// Package httpapi serves the REST API (F-4.7.1): /v1/analyze, /v1/analyses/{id},
// /v1/submissions, /v1/brands, /v1/lists/{allow|block}, /v1/stats, /v1/webhooks,
// /health, /metrics. OpenAPI 3 description lives in api/openapi.yaml.
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/buildinfo"
)

// Server holds dependencies for handlers.
type Server struct {
	app     *app.App
	log     zerolog.Logger
	limiter *rateLimiter
	oidc    *oidcAuth
}

// New builds the server.
func New(a *app.App) *Server {
	s := &Server{app: a, log: a.Log.With().Str("component", "http").Logger(), limiter: newRateLimiter(a.Cfg.Server.RateLimitRPS)}
	if a.Cfg.Auth.OIDC.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if auth, err := newOIDCAuth(ctx, a.Cfg.Auth.OIDC); err != nil {
			s.log.Error().Err(err).Msg("oidc initialization")
		} else {
			s.oidc = auth
		}
	}
	return s
}

// Routes mounts the API onto r.
func (s *Server) Routes(r chi.Router) {
	r.Get("/health", s.handleHealth)
	r.Method(http.MethodGet, "/metrics", promhttp.Handler())
	r.Get("/auth/oidc/login", s.handleOIDCLogin)
	r.Get("/auth/oidc/callback", s.handleOIDCCallback)
	r.Get("/auth/logout", s.handleOIDCLogout)

	r.Route("/v1", func(v1 chi.Router) {
		v1.Use(s.authenticate)
		v1.Use(s.rateLimit)

		v1.With(s.allowAnonymous).Post("/analyze", s.handleAnalyze)
		v1.With(s.allowAnonymous).Get("/analyses/{id}", s.handleGetAnalysis)
		v1.With(requireRole(RoleUser, RoleAnalyst, RoleAdmin)).Post("/submissions/{id}/report", s.handleReportSubmission)
		v1.Get("/demos", s.handleDemos)

		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Get("/submissions", s.handleListSubmissions)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Get("/submissions/{id}", s.handleGetAnalysis)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Patch("/submissions/{id}", s.handleReview)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Post("/submissions/{id}/block-domain", s.handleBlockDomain)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Post("/submissions/{id}/incident", s.handleCreateIncident)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Delete("/submissions/{id}", s.handleDeleteSubmission)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Get("/campaigns", s.handleCampaigns)

		v1.Get("/brands", s.handleListBrands)
		v1.With(requireRole(RoleAdmin)).Post("/brands", s.handleAddBrand)

		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Get("/lists/{kind}", s.handleListEntries)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Post("/lists/{kind}", s.handleAddEntry)
		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Delete("/lists/{kind}/{value}", s.handleRemoveEntry)

		v1.With(requireRole(RoleAnalyst, RoleAdmin)).Get("/stats", s.handleStats)
		v1.With(requireRole(RoleAdmin)).Get("/webhooks", s.handleListWebhooks)
		v1.With(requireRole(RoleAdmin)).Post("/webhooks", s.handleCreateWebhook)
		v1.With(requireRole(RoleAdmin)).Delete("/webhooks/{id}", s.handleDeleteWebhook)
		v1.Get("/signals", s.handleSignals)
	})
}

// Handler returns a fully wired http.Handler with standard middleware.
func (s *Server) Handler(mount func(chi.Router)) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.logRequests)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(secureHeaders)
	s.Routes(r)
	if mount != nil {
		mount(r)
	}
	return r
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if r.URL.Path == "/metrics" || r.URL.Path == "/health" {
			return
		}
		s.log.Info().
			Str("method", r.Method).Str("path", r.URL.Path).Int("status", ww.Status()).
			Dur("dur", time.Since(start)).Str("ip", r.RemoteAddr).Str("req", middleware.GetReqID(r.Context())).
			Msg("request")
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"status":  "ok",
		"version": buildinfo.Version,
		"edition": buildinfo.Edition,
		"signals": s.app.Registry.Len(),
		"brands":  len(s.app.Brands.Brands()),
		"llm":     s.app.LLM != nil,
		"store":   s.app.Store != nil,
	}
	if s.app.LLM != nil {
		out["llm_providers"] = s.app.LLM.Providers()
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- helpers ----------------------------------------------------------------

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: code, Message: msg})
}
