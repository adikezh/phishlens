// Package metrics exposes Prometheus collectors for /metrics (ТЗ §5: analyses,
// verdicts, stage latency, external API errors, LLM tokens).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	AnalysesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "phishlens", Name: "analyses_total", Help: "Analyses by channel, kind and verdict.",
	}, []string{"channel", "kind", "verdict"})

	StageDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "phishlens", Name: "stage_duration_seconds", Help: "Pipeline stage latency.",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"stage"})

	AnalysisDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "phishlens", Name: "analysis_duration_seconds", Help: "End-to-end analysis latency.",
		Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 20},
	})

	ExternalErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "phishlens", Name: "external_errors_total", Help: "Failures of external services.",
	}, []string{"service"})

	LLMTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "phishlens", Name: "llm_tokens_total", Help: "LLM tokens by provider and direction.",
	}, []string{"provider", "direction"})

	LLMCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "phishlens", Name: "llm_cache_hits_total", Help: "Explanations served from cache.",
	})

	SignalsFired = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "phishlens", Name: "signals_fired_total", Help: "Signal occurrences by id.",
	}, []string{"signal"})
)
