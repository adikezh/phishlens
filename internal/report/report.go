// Package report produces periodic awareness reports (F-4.8.1), anonymised
// training cards (F-4.8.2) and IOC exports (F-4.8.3).
package report

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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

// ExportIOC — TODO(F-4.8.3): STIX 2.1 bundle / MISP event from confirmed submissions.
func ExportIOC(_ context.Context, _ store.Store, _ time.Time, format string) ([]byte, error) {
	return nil, fmt.Errorf("%w: ioc export %s", ErrNotImplemented, format)
}
