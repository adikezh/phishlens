package app

import (
	"context"
	"errors"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/i18n"
	"github.com/phishlens/phishlens/internal/llm"
	"github.com/phishlens/phishlens/internal/metrics"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/score"
	"github.com/phishlens/phishlens/internal/signals"
)

// Request is one analysis job.
type Request struct {
	ID          string
	Channel     domain.Channel
	Kind        domain.Kind
	Data        []byte // eml / msg / image bytes, or text when Kind == text
	SubmittedBy string
	OrgID       string
	Lang        string
	NoLLM       bool
	NoStore     bool
}

// Analyzer runs the seven-stage pipeline (ТЗ §2).
type Analyzer struct {
	app *App
}

// NewAnalyzer binds the pipeline to the app.
func NewAnalyzer(a *App) *Analyzer { return &Analyzer{app: a} }

// Analyze executes parse → brand → heuristics → reputation → LLM → semantic → score,
// persists the result and fans out notifications. External-stage failures degrade
// with warnings instead of failing the request.
func (an *Analyzer) Analyze(ctx context.Context, req Request) (*domain.Submission, error) {
	a := an.app
	start := time.Now()
	timeout := a.Cfg.Analysis.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lang := i18n.Normalize(req.Lang)
	if req.Lang == "" {
		lang = i18n.Normalize(a.Cfg.Analysis.Language)
	}
	if req.Channel == "" {
		req.Channel = domain.ChannelAPI
	}
	sub := &domain.Submission{
		ID:          req.ID,
		Channel:     req.Channel,
		Kind:        req.Kind,
		SubmittedBy: req.SubmittedBy,
		OrgID:       req.OrgID,
		ReceivedAt:  time.Now().UTC(),
		Status:      domain.StatusAnalyzed,
	}
	if sub.ID == "" {
		sub.ID = ulid.Make().String()
	}
	var warnings []string
	var stages []domain.Stage
	stage := func(name string, fn func() error) {
		t := time.Now()
		err := fn()
		d := time.Since(t)
		metrics.StageDuration.WithLabelValues(name).Observe(d.Seconds())
		st := domain.Stage{Name: name, DurationMs: int(d.Milliseconds())}
		if err != nil {
			st.Error = err.Error()
		}
		stages = append(stages, st)
	}

	// 1. parse
	var mail *domain.ParsedMail
	var parseErr error
	stage("parse", func() error {
		mail, parseErr = a.Parser.Parse(ctx, req.Kind, req.Data)
		if parseErr != nil && errors.Is(parseErr, parse.ErrOCRUnavailable) {
			warnings = append(warnings, "ocr_unavailable: image text was not extracted")
			parseErr = nil
		}
		return parseErr
	})
	if parseErr != nil {
		return nil, parseErr
	}
	if mail == nil {
		return nil, parse.ErrEmpty
	}
	sub.Message = mail

	// 2. brand
	var brand *domain.BrandMatch
	stage("brand", func() error {
		brand = a.Brands.Match(mail)
		return nil
	})

	in := &signals.Input{
		Mail: mail, Brand: brand, Lang: lang, OrgID: req.OrgID,
		Data: a.Data, Brands: a.Brands,
	}
	if a.Rep != nil {
		in.Rep = a.Rep // a typed nil must not become a non-nil interface
	}
	if a.Sandbox != nil {
		in.Sandbox = a.Sandbox
	}
	if a.Store != nil {
		in.Lists = &storeLists{st: a.Store, org: req.OrgID}
	}

	// 3. local heuristics
	var all []domain.Signal
	stage("heuristics", func() error {
		sigs, errs := a.Registry.RunCategories(ctx, in,
			domain.CategoryHeader, domain.CategoryAuth, domain.CategoryDomain, domain.CategoryLink,
			domain.CategoryAttachment, domain.CategoryContent, domain.CategoryBrand)
		all = append(all, sigs...)
		for _, e := range errs {
			a.Log.Warn().Err(e).Msg("heuristic failed")
			warnings = append(warnings, "check_failed: "+e.Error())
		}
		return nil
	})

	// 4. reputation (network, bounded)
	stage("reputation", func() error {
		rt := a.Cfg.Reputation.Timeout
		if rt <= 0 {
			rt = 3 * time.Second
		}
		rctx, rcancel := context.WithTimeout(ctx, rt)
		defer rcancel()
		sigs, errs := a.Registry.RunCategories(rctx, in, domain.CategoryReputation)
		all = append(all, sigs...)
		for _, e := range errs {
			metrics.ExternalErrors.WithLabelValues("reputation").Inc()
			warnings = append(warnings, "reputation_degraded: "+e.Error())
		}
		return nil
	})

	// 5. LLM explanation (optional)
	if a.LLM != nil && !req.NoLLM {
		stage("llm", func() error {
			prelim := a.Score.Evaluate(score.Input{Signals: all, Brand: brand, Lang: lang})
			ex, err := a.LLM.Explain(ctx, llm.ExplainInput{Mail: mail, Signals: all, Brand: brand, Score: prelim.Score, Lang: lang})
			if err != nil {
				metrics.ExternalErrors.WithLabelValues("llm").Inc()
				warnings = append(warnings, "llm_unavailable: "+err.Error())
				return err
			}
			if ex.Cached {
				metrics.LLMCacheHits.Inc()
			}
			in.LLM = ex
			return nil
		})
	}

	// 6. semantic signal from the LLM opinion
	if in.LLM != nil {
		stage("semantic", func() error {
			sigs, _ := a.Registry.RunCategories(ctx, in, domain.CategorySemantic)
			all = append(all, sigs...)
			return nil
		})
	}

	// 7. score & verdict
	var analysis *domain.Analysis
	stage("score", func() error {
		analysis = a.Score.Evaluate(score.Input{
			Signals: all, Brand: brand, LLM: in.LLM, Lang: lang,
			Warnings: warnings, DurationMs: int(time.Since(start).Milliseconds()),
		})
		return nil
	})
	analysis.Stages = stages
	analysis.DurationMs = int(time.Since(start).Milliseconds())
	sub.Result = analysis

	metrics.AnalysesTotal.WithLabelValues(string(sub.Channel), string(sub.Kind), string(analysis.Verdict)).Inc()
	metrics.AnalysisDuration.Observe(time.Since(start).Seconds())
	for _, s := range analysis.Signals {
		metrics.SignalsFired.WithLabelValues(s.ID).Inc()
	}

	// 8. persist (best effort: a storage failure must not hide the verdict)
	if a.Store != nil && !req.NoStore {
		if err := a.Store.SaveSubmission(context.WithoutCancel(ctx), sub, a.Cfg.Storage.StoreBodies); err != nil {
			a.Log.Error().Err(err).Str("id", sub.ID).Msg("store submission")
			analysis.Warnings = append(analysis.Warnings, "store_failed: "+err.Error())
		}
	}

	// 9. notify (async)
	if a.Notify != nil {
		go a.Notify.Notify(context.WithoutCancel(ctx), sub)
	}

	a.Log.Info().
		Str("id", sub.ID).Str("channel", string(sub.Channel)).Str("kind", string(sub.Kind)).
		Int("score", analysis.Score).Str("verdict", string(analysis.Verdict)).
		Int("signals", len(analysis.Signals)).Int("ms", analysis.DurationMs).
		Msg("analyzed")
	return sub, nil
}
