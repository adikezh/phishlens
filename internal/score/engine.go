package score

import (
	"math"
	"sort"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/i18n"
)

// Well-known signal IDs the hard rules depend on.
const (
	sigOrgBlocklist = "reputation.org_blocklist"
	sigOrgAllowlist = "reputation.org_allowlist"
)

// strongTechnical is the weight at which a single heuristic counts as "strong"
// for needs_review conflict detection.
const strongTechnical = 25

// Engine evaluates signals.
type Engine struct {
	w *Weights
}

// NewEngine returns an engine; nil weights fall back to defaults.
func NewEngine(w *Weights) *Engine {
	if w == nil {
		w = &Weights{Thresholds: DefaultThresholds, Signals: map[string]int{}}
	}
	return &Engine{w: w}
}

// Weights exposes the active table (for /v1/stats and weights tune).
func (e *Engine) Weights() *Weights { return e.w }

// Input is what the engine needs.
type Input struct {
	Signals    []domain.Signal
	Brand      *domain.BrandMatch
	LLM        *domain.LLMExplain
	Lang       string
	Warnings   []string
	DurationMs int
	Stages     []domain.Stage
}

// Evaluate computes the Analysis.
func (e *Engine) Evaluate(in Input) *domain.Analysis {
	sigs := make([]domain.Signal, len(in.Signals))
	copy(sigs, in.Signals)

	// 1. configured weights override defaults baked into checks
	for i := range sigs {
		if w, ok := e.w.Signals[sigs[i].ID]; ok {
			sigs[i].Weight = w
		}
	}

	// 2. raw sum
	raw := 0.0
	for _, s := range sigs {
		raw += s.Contribution()
	}
	score := clamp(int(math.Round(raw)), 0, 100)

	// 3. thresholds
	th := e.w.Thresholds
	verdict := domain.VerdictClean
	switch {
	case score >= th.Phishing:
		verdict = domain.VerdictPhishing
	case score >= th.Suspicious:
		verdict = domain.VerdictSuspicious
	}

	// 4. hard rules (F-4.5.3)
	blocklisted, allowlisted, tiHit := false, false, false
	strongest := 0.0
	for _, s := range sigs {
		switch s.ID {
		case sigOrgBlocklist:
			blocklisted = true
		case sigOrgAllowlist:
			allowlisted = true
		}
		if s.Source == domain.SourceTI && s.Weight > 0 {
			tiHit = true
		}
		if s.Category != domain.CategorySemantic && s.Weight >= strongTechnical && s.Confidence >= 0.8 {
			strongest = math.Max(strongest, s.Contribution())
		}
	}
	if blocklisted {
		verdict = domain.VerdictPhishing
		score = max(score, th.Phishing)
	}
	if tiHit && verdict == domain.VerdictClean {
		verdict = domain.VerdictSuspicious
		score = max(score, th.Suspicious)
	}

	// 5. conflicts → needs_review (F-4.5.2)
	llmClean := in.LLM != nil && in.LLM.VerdictOpinion == "clean"
	if !blocklisted {
		if strongest > 0 && llmClean && verdict != domain.VerdictClean {
			verdict = domain.VerdictNeedsReview
		}
		if allowlisted && score >= th.Phishing {
			verdict = domain.VerdictNeedsReview
		}
	}

	// 6. order signals by absolute contribution for the UI
	sort.SliceStable(sigs, func(i, j int) bool {
		return math.Abs(sigs[i].Contribution()) > math.Abs(sigs[j].Contribution())
	})

	a := &domain.Analysis{
		Score:      score,
		Verdict:    verdict,
		Confidence: confidence(score, th, sigs, in.LLM),
		Signals:    sigs,
		AttackType: attackType(sigs, in.LLM, verdict),
		Brand:      in.Brand,
		LLM:        in.LLM,
		Warnings:   in.Warnings,
		DurationMs: in.DurationMs,
		Stages:     in.Stages,
	}
	a.Recommendations = recommendations(a, in.Lang)
	return a
}

// confidence grows with the distance from the nearest threshold and the number
// of agreeing signals; LLM agreement adds a little.
func confidence(score int, th Thresholds, sigs []domain.Signal, llm *domain.LLMExplain) float64 {
	dist := math.Min(math.Abs(float64(score-th.Phishing)), math.Abs(float64(score-th.Suspicious)))
	c := 0.5 + math.Min(0.3, dist/100)
	positives := 0
	for _, s := range sigs {
		if s.Weight > 0 && s.Category != domain.CategorySemantic {
			positives++
		}
	}
	c += math.Min(0.15, float64(positives)*0.03)
	if llm != nil {
		agree := (llm.VerdictOpinion == "phishing" && score >= th.Phishing) ||
			(llm.VerdictOpinion == "clean" && score < th.Suspicious) ||
			(llm.VerdictOpinion == "suspicious" && score >= th.Suspicious && score < th.Phishing)
		if agree {
			c += 0.05
		} else {
			c -= 0.1
		}
	}
	return math.Round(math.Max(0.1, math.Min(0.99, c))*100) / 100
}

// attackType prefers the validated LLM opinion, else infers from signals.
func attackType(sigs []domain.Signal, llm *domain.LLMExplain, verdict domain.Verdict) domain.AttackType {
	if llm != nil && domain.ValidAttackType(llm.AttackType) && llm.AttackType != string(domain.AttackNone) {
		return domain.AttackType(llm.AttackType)
	}
	has := func(prefix string) bool {
		for _, s := range sigs {
			if strings.HasPrefix(s.ID, prefix) && s.Weight > 0 {
				return true
			}
		}
		return false
	}
	switch {
	case verdict == domain.VerdictClean:
		return domain.AttackNone
	case has("attachment."):
		return domain.AttackMalware
	case has("content.bec_pattern"):
		return domain.AttackBEC
	case has("content.finance_request") && !has("link."):
		return domain.AttackInvoiceFraud
	case has("content.credential_request") || has("link.") || has("brand."):
		return domain.AttackCredentialHarvesting
	default:
		return domain.AttackSpam
	}
}

// recommendations produces localised, signal-aware advice (F-4.4.5 works without LLM).
func recommendations(a *domain.Analysis, lang string) []string {
	var out []string
	out = append(out, i18n.T(lang, "recommend."+string(a.Verdict)))
	if a.Verdict == domain.VerdictClean {
		return out
	}
	has := func(prefix string) bool {
		for _, s := range a.Signals {
			if strings.HasPrefix(s.ID, prefix) && s.Weight > 0 {
				return true
			}
		}
		return false
	}
	if has("link.") || has("brand.") {
		out = append(out, i18n.T(lang, "recommend.no_click"))
	}
	if has("content.credential_request") {
		out = append(out, i18n.T(lang, "recommend.no_credentials"))
	}
	if has("attachment.") {
		out = append(out, i18n.T(lang, "recommend.no_attachment"))
	}
	if has("content.bec_pattern") || has("content.finance_request") || has("domain.free_mail_org") {
		out = append(out, i18n.T(lang, "recommend.verify_sender"))
	}
	if a.LLM != nil && a.LLM.RecommendedAction != "" {
		out = append(out, a.LLM.RecommendedAction)
	}
	out = append(out, i18n.T(lang, "recommend.report"))
	return out
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
