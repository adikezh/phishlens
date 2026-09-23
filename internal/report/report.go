// Package report produces periodic awareness reports (F-4.8.1), anonymised
// training cards (F-4.8.2) and IOC exports (F-4.8.3).
package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phishlens/phishlens/internal/store"
)

// ErrNotImplemented marks formats not yet supported.
var ErrNotImplemented = errors.New("report: not implemented")

// Generate renders a report for [since, now). Markdown is implemented; docx/pdf are TODO
// (nguyenthenguyen/docx, johnfercher/maroto).
func Generate(ctx context.Context, st store.Store, orgID string, since time.Time, format string) ([]byte, error) {
	stats, err := st.Stats(ctx, orgID, since)
	if err != nil {
		return nil, err
	}
	switch format {
	case "md", "markdown":
		return []byte(markdown(stats)), nil
	case "docx", "pdf":
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, format)
	default:
		return nil, fmt.Errorf("report: unknown format %q", format)
	}
}

func markdown(s *store.Stats) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PhishLens — отчёт с %s\n\n", s.Since.Format("2006-01-02"))
	fmt.Fprintf(&b, "Всего обращений: **%d**\n\n", s.Total)
	b.WriteString("## Вердикты\n\n| Вердикт | Кол-во |\n|---|---|\n")
	for _, v := range []string{"phishing", "suspicious", "needs_review", "clean"} {
		fmt.Fprintf(&b, "| %s | %d |\n", v, s.ByVerdict[v])
	}
	b.WriteString("\n## Статусы обработки\n\n| Статус | Кол-во |\n|---|---|\n")
	for k, v := range s.ByStatus {
		fmt.Fprintf(&b, "| %s | %d |\n", k, v)
	}
	b.WriteString("\n## Типы атак\n\n| Тип | Кол-во |\n|---|---|\n")
	for k, v := range s.ByAttackType {
		fmt.Fprintf(&b, "| %s | %d |\n", k, v)
	}
	b.WriteString("\n## Топ имитируемых брендов\n\n")
	for _, nc := range s.TopBrands {
		fmt.Fprintf(&b, "- %s — %d\n", nc.Name, nc.Count)
	}
	b.WriteString("\n## Топ сигналов\n\n")
	for _, nc := range s.TopSignals {
		fmt.Fprintf(&b, "- `%s` — %d\n", nc.Name, nc.Count)
	}
	fmt.Fprintf(&b, "\nСреднее время анализа: %d мс\n", s.AvgDuration)
	// TODO(F-4.8.1): reaction time, departments (needs users/orgs), top tactics (LLM).
	return b.String()
}

// ExportIOC exports privacy-safe indicators from confirmed phishing cases.
// It never reads or emits stored message bodies.
func ExportIOC(ctx context.Context, st store.Store, since time.Time, format string) ([]byte, error) {
	iocs, err := st.ListIOCs(ctx, "", since)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(format) {
	case "stix", "stix2", "stix21":
		return json.MarshalIndent(stixBundle(iocs), "", "  ")
	case "misp":
		return json.MarshalIndent(buildMISPEvent(iocs), "", "  ")
	default:
		return nil, fmt.Errorf("report: unknown ioc format %q (use stix or misp)", format)
	}
}

type stixBundlePayload struct {
	Type        string          `json:"type"`
	SpecVersion string          `json:"spec_version"`
	ID          string          `json:"id"`
	Created     string          `json:"created"`
	Modified    string          `json:"modified"`
	Objects     []stixIndicator `json:"objects"`
}

type stixIndicator struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
	PatternType string   `json:"pattern_type"`
	Pattern     string   `json:"pattern"`
	ValidFrom   string   `json:"valid_from"`
	Labels      []string `json:"labels"`
	Description string   `json:"description"`
}

func stixBundle(iocs []store.IOC) stixBundlePayload {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	b := stixBundlePayload{Type: "bundle", SpecVersion: "2.1", ID: "bundle--" + uuid.NewString(), Created: now, Modified: now}
	for _, i := range iocs {
		observable, ok := map[string]string{"domain": "domain-name:value", "url": "url:value", "sha256": "file:hashes.'SHA-256'"}[i.Kind]
		if !ok {
			continue
		}
		stamp := i.CreatedAt.UTC().Format(time.RFC3339Nano)
		b.Objects = append(b.Objects, stixIndicator{
			Type: "indicator", SpecVersion: "2.1", ID: "indicator--" + uuid.NewString(),
			Created: now, Modified: now, PatternType: "stix", Pattern: "[" + observable + " = '" + stixQuote(i.Value) + "']",
			ValidFrom: stamp, Labels: []string{"phishing", "phishlens"}, Description: "IOC exported from confirmed PhishLens phishing submission " + i.SubmissionID,
		})
	}
	return b
}

func stixQuote(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

type mispEventPayload struct {
	Event mispEvent `json:"Event"`
}
type mispEvent struct {
	Info          string          `json:"info"`
	Distribution  string          `json:"distribution"`
	ThreatLevelID string          `json:"threat_level_id"`
	Analysis      string          `json:"analysis"`
	Published     bool            `json:"published"`
	Timestamp     string          `json:"timestamp"`
	Attribute     []mispAttribute `json:"Attribute"`
}
type mispAttribute struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Value    string `json:"value"`
	ToIDs    bool   `json:"to_ids"`
	Comment  string `json:"comment"`
}

func buildMISPEvent(iocs []store.IOC) mispEventPayload {
	e := mispEvent{Info: "PhishLens confirmed phishing IOC export", Distribution: "0", ThreatLevelID: "2", Analysis: "0", Timestamp: fmt.Sprint(time.Now().Unix())}
	for _, i := range iocs {
		typ := map[string]string{"domain": "domain", "url": "url", "sha256": "sha256"}[i.Kind]
		if typ == "" {
			continue
		}
		e.Attribute = append(e.Attribute, mispAttribute{Type: typ, Category: "Network activity", Value: i.Value, ToIDs: true, Comment: "PhishLens submission " + i.SubmissionID})
	}
	return mispEventPayload{Event: e}
}
