// Package web serves the operator UI (F-4.7.2): html/template + htmx +
// Tailwind CDN. The analysis page and operator pages are deliberately server
// rendered shells; data actions use the authenticated REST API from the browser.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/addins"
	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/buildinfo"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/httpapi"
	"github.com/phishlens/phishlens/internal/i18n"
)

//go:embed templates/*.html
var templateFS embed.FS

// UI holds parsed templates.
type UI struct {
	app  *app.App
	log  zerolog.Logger
	tmpl *template.Template
}

// New parses templates.
func New(a *app.App) (*UI, error) {
	funcs := template.FuncMap{
		"t": i18n.T,
		"verdictClass": func(v domain.Verdict) string {
			switch v {
			case domain.VerdictPhishing:
				return "bg-red-600"
			case domain.VerdictSuspicious:
				return "bg-amber-500"
			case domain.VerdictNeedsReview:
				return "bg-violet-600"
			default:
				return "bg-emerald-600"
			}
		},
		"signalClass": func(w int) string {
			if w < 0 {
				return "border-emerald-300 bg-emerald-50"
			}
			if w >= 25 {
				return "border-red-300 bg-red-50"
			}
			return "border-amber-300 bg-amber-50"
		},
		"pct":   func(v float64) int { return int(v * 100) },
		"lower": strings.ToLower,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: templates: %w", err)
	}
	return &UI{app: a, log: a.Log.With().Str("component", "web").Logger(), tmpl: tmpl}, nil
}

// Routes mounts UI routes.
func (u *UI) Routes(r chi.Router) {
	r.Get("/", u.handleIndex)
	r.Post("/ui/analyze", u.handleAnalyze)
	r.Get("/ui/queue", u.handleQueue)
	r.Get("/ui/campaigns", u.handleCampaigns)
	r.Get("/ui/dashboard", u.handleDashboard)
	r.Get("/ui/brands", u.handleBrands)
	sub, _ := fs.Sub(addins.FS, ".")
	r.Handle("/addins/*", http.StripPrefix("/addins/", http.FileServer(http.FS(sub))))
}

type pageData struct {
	Version string
	Edition string
	Lang    string
	Title   string
	Mode    string
	Demos   []app.Demo
	Signals int
	Brands  int
	LLM     bool
	OIDC    bool
}

func (u *UI) handleIndex(w http.ResponseWriter, r *http.Request) {
	d := pageData{
		Version: buildinfo.Version, Edition: buildinfo.Edition,
		Lang:    i18n.Normalize(u.app.Cfg.Analysis.Language),
		Demos:   app.Demos(),
		Signals: u.app.Registry.Len(),
		Brands:  len(u.app.Brands.Brands()),
		LLM:     u.app.LLM != nil,
		Title:   "Проверка письма",
	}
	u.render(w, "index.html", d)
}

func (u *UI) operatorPage(w http.ResponseWriter, mode, title string) {
	u.render(w, "operator.html", pageData{
		Version: buildinfo.Version, Edition: buildinfo.Edition,
		Lang: i18n.Normalize(u.app.Cfg.Analysis.Language), Title: title, Mode: mode,
		Signals: u.app.Registry.Len(), Brands: len(u.app.Brands.Brands()),
		OIDC: u.app.Cfg.Auth.OIDC.Enabled,
	})
}

func (u *UI) handleQueue(w http.ResponseWriter, _ *http.Request) {
	u.operatorPage(w, "queue", "Очередь ИБ")
}

func (u *UI) handleCampaigns(w http.ResponseWriter, _ *http.Request) {
	u.operatorPage(w, "campaigns", "Кампании")
}

func (u *UI) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	u.operatorPage(w, "dashboard", "Дашборд")
}

func (u *UI) handleBrands(w http.ResponseWriter, _ *http.Request) {
	u.operatorPage(w, "brands", "Бренды")
}

type resultData struct {
	Sub   *domain.Submission
	Lang  string
	Error string
}

func (u *UI) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if !u.app.Cfg.Auth.AnonymousAnalyze && httpapi.PrincipalFrom(r.Context()).Role == httpapi.RoleAnonymous {
		u.render(w, "result.html", resultData{Error: "Анонимный анализ отключён — войдите или используйте API-ключ."})
		return
	}
	maxBytes := int64(u.app.Cfg.Server.MaxUploadMB) << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+4096)
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		u.render(w, "result.html", resultData{Error: "Файл слишком большой: " + err.Error()})
		return
	}
	lang := i18n.Normalize(r.FormValue("lang"))
	req := app.Request{Channel: domain.ChannelWeb, Lang: lang, NoLLM: r.FormValue("no_llm") == "on", Department: strings.TrimSpace(r.FormValue("department"))}
	if f, hdr, err := r.FormFile("file"); err == nil && hdr.Size > 0 {
		defer f.Close()
		data, _ := io.ReadAll(io.LimitReader(f, maxBytes+1))
		kind, err := httpapi.DetectKind(hdr.Filename, hdr.Header.Get("Content-Type"), data)
		if err != nil {
			u.render(w, "result.html", resultData{Error: err.Error()})
			return
		}
		req.Kind, req.Data = kind, data
	} else if demo := r.FormValue("demo"); demo != "" {
		b, ok := app.DemoBytes(demo)
		if !ok {
			u.render(w, "result.html", resultData{Error: "Неизвестный пример"})
			return
		}
		req.Kind, req.Data = domain.KindEML, b
	} else if t := strings.TrimSpace(r.FormValue("text")); t != "" {
		req.Kind, req.Data = domain.KindText, []byte(t)
	} else {
		u.render(w, "result.html", resultData{Error: "Вставьте текст письма или загрузите файл."})
		return
	}
	sub, err := u.app.Analyzer.Analyze(r.Context(), req)
	if err != nil {
		u.render(w, "result.html", resultData{Error: err.Error()})
		return
	}
	u.render(w, "result.html", resultData{Sub: sub, Lang: lang})
}

func (u *UI) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := u.tmpl.ExecuteTemplate(w, name, data); err != nil {
		u.log.Error().Err(err).Str("template", name).Msg("render")
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
