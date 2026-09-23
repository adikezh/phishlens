package score

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
)

func sig(id string, cat domain.Category, w int, conf float64) domain.Signal {
	return domain.Signal{ID: id, Category: cat, Weight: w, Confidence: conf, Source: domain.SourceHeuristic}
}

func engine() *Engine {
	return NewEngine(&Weights{Thresholds: DefaultThresholds, Signals: map[string]int{"header.replyto_mismatch": 50}})
}

func TestThresholdsAndClamp(t *testing.T) {
	e := engine()
	a := e.Evaluate(Input{Signals: []domain.Signal{sig("x", domain.CategoryLink, 30, 1), sig("y", domain.CategoryContent, 10, 0.5)}})
	require.Equal(t, 35, a.Score)
	require.Equal(t, domain.VerdictClean, a.Verdict)

	a = e.Evaluate(Input{Signals: []domain.Signal{sig("x", domain.CategoryLink, 30, 1), sig("y", domain.CategoryContent, 20, 1)}})
	require.Equal(t, domain.VerdictSuspicious, a.Verdict)

	a = e.Evaluate(Input{Signals: []domain.Signal{sig("x", domain.CategoryLink, 90, 1), sig("y", domain.CategoryContent, 90, 1)}})
	require.Equal(t, 100, a.Score, "clamped to 100")
	require.Equal(t, domain.VerdictPhishing, a.Verdict)

	a = e.Evaluate(Input{Signals: []domain.Signal{sig("auth.aligned_official", domain.CategoryAuth, -40, 1)}})
	require.Equal(t, 0, a.Score, "clamped to 0")
}

func TestWeightOverride(t *testing.T) {
	a := engine().Evaluate(Input{Signals: []domain.Signal{sig("header.replyto_mismatch", domain.CategoryHeader, 15, 1)}})
	require.Equal(t, 50, a.Score, "weights.yaml overrides the check's default")
	require.Equal(t, 50, a.Signals[0].Weight)
}

func TestHardRules(t *testing.T) {
	e := engine()
	// blocklist → phishing regardless of the sum
	a := e.Evaluate(Input{Signals: []domain.Signal{sig(sigOrgBlocklist, domain.CategoryReputation, 100, 1), sig("auth.aligned_official", domain.CategoryAuth, -40, 1)}})
	require.Equal(t, domain.VerdictPhishing, a.Verdict)
	require.GreaterOrEqual(t, a.Score, 70)

	// TI hit → at least suspicious
	ti := sig("reputation.domain_listed", domain.CategoryReputation, 5, 1)
	ti.Source = domain.SourceTI
	a = e.Evaluate(Input{Signals: []domain.Signal{ti}})
	require.Equal(t, domain.VerdictSuspicious, a.Verdict)
	require.GreaterOrEqual(t, a.Score, 40)
}

func TestNeedsReviewConflicts(t *testing.T) {
	e := engine()
	strong := sig("auth.dmarc_fail", domain.CategoryAuth, 25, 1)
	llmClean := &domain.LLMExplain{VerdictOpinion: "clean"}
	a := e.Evaluate(Input{Signals: []domain.Signal{strong, sig("x", domain.CategoryLink, 20, 1)}, LLM: llmClean})
	require.Equal(t, domain.VerdictNeedsReview, a.Verdict, "strong technical signal vs LLM clean")

	// LLM cannot turn a strong signal into clean by itself: semantic weight is bounded
	llmSig := sig("semantic.llm_clean", domain.CategorySemantic, -15, 1)
	llmSig.Source = domain.SourceLLM
	a = e.Evaluate(Input{Signals: []domain.Signal{strong, sig("x", domain.CategoryLink, 30, 1), llmSig}, LLM: llmClean})
	require.NotEqual(t, domain.VerdictClean, a.Verdict)

	// allowlist vs high score
	a = e.Evaluate(Input{Signals: []domain.Signal{sig(sigOrgAllowlist, domain.CategoryReputation, -30, 1), sig("x", domain.CategoryLink, 60, 1), sig("y", domain.CategoryAuth, 50, 1)}})
	require.Equal(t, domain.VerdictNeedsReview, a.Verdict)
}

func TestAttackTypeAndRecommendations(t *testing.T) {
	e := engine()
	a := e.Evaluate(Input{Lang: "ru", Signals: []domain.Signal{sig("attachment.dangerous_ext", domain.CategoryAttachment, 30, 1), sig("content.urgency", domain.CategoryContent, 10, 1)}})
	require.Equal(t, domain.AttackMalware, a.AttackType)
	require.NotEmpty(t, a.Recommendations)

	a = e.Evaluate(Input{Lang: "en", Signals: []domain.Signal{sig("content.bec_pattern", domain.CategoryContent, 40, 1), sig("domain.free_mail_org", domain.CategoryDomain, 15, 1)}})
	require.Equal(t, domain.AttackBEC, a.AttackType)

	a = e.Evaluate(Input{Signals: []domain.Signal{sig("x", domain.CategoryContent, 50, 1)}, LLM: &domain.LLMExplain{VerdictOpinion: "phishing", AttackType: "invoice_fraud"}})
	require.Equal(t, domain.AttackInvoiceFraud, a.AttackType, "validated LLM attack type wins")

	a = e.Evaluate(Input{Signals: nil})
	require.Equal(t, domain.AttackNone, a.AttackType)
	require.Equal(t, domain.VerdictClean, a.Verdict)
}

func TestSignalsSortedByContribution(t *testing.T) {
	a := engine().Evaluate(Input{Signals: []domain.Signal{sig("a", domain.CategoryContent, 5, 1), sig("b", domain.CategoryLink, 30, 1), sig("c", domain.CategoryAuth, -40, 1)}})
	require.Equal(t, "c", a.Signals[0].ID)
	require.Equal(t, "b", a.Signals[1].ID)
}
