// Package report produces periodic awareness reports (F-4.8.1), anonymised
// training cards (F-4.8.2) and IOC exports (F-4.8.3).
package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/store"
)

// ErrNotImplemented marks formats not yet supported.
var ErrNotImplemented = errors.New("report: not implemented")

// Generate renders a report for [since, now) in Markdown, DOCX, or PDF.
func Generate(ctx context.Context, st store.Store, orgID string, since time.Time, format string) ([]byte, error) {
	stats, err := st.Stats(ctx, orgID, since)
	if err != nil {
		return nil, err
	}
	switch format {
	case "md", "markdown":
		return []byte(markdown(stats)), nil
	case "docx":
		return docx(stats)
	case "pdf":
		return pdf(stats), nil
	case "awareness", "html":
		return ExportAwareness(ctx, st, orgID, since)
	default:
		return nil, fmt.Errorf("report: unknown format %q", format)
	}
}

func reportLines(s *store.Stats) []string {
	lines := []string{
		"PhishLens report from " + s.Since.Format("2006-01-02"),
		fmt.Sprintf("Total submissions: %d", s.Total),
		"",
		"Verdicts:",
	}
	for _, k := range []string{"phishing", "suspicious", "needs_review", "clean"} {
		lines = append(lines, fmt.Sprintf("%s: %d", k, s.ByVerdict[k]))
	}
	lines = append(lines, "", "Statuses:")
	lines = appendSortedCounts(lines, s.ByStatus)
	lines = append(lines, "", "Attack types:")
	lines = appendSortedCounts(lines, s.ByAttackType)
	lines = append(lines, "", "Departments:")
	lines = appendSortedCounts(lines, s.ByDepartment)
	lines = append(lines, "", "Top brands:")
	for _, nc := range s.TopBrands {
		lines = append(lines, fmt.Sprintf("%s: %d", nc.Name, nc.Count))
	}
	lines = append(lines, "", "Top signals:")
	for _, nc := range s.TopSignals {
		lines = append(lines, fmt.Sprintf("%s: %d", nc.Name, nc.Count))
	}
	lines = append(lines, "", "Top tactics:")
	lines = appendSortedCounts(lines, tacticCounts(s.TopSignals))
	lines = append(lines, "", fmt.Sprintf("Average analysis time: %d ms", s.AvgDuration), fmt.Sprintf("Average review time: %d ms", s.AvgReviewDuration))
	return lines
}

func appendSortedCounts(lines []string, counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s: %d", k, counts[k]))
	}
	return lines
}

func docx(s *store.Stats) ([]byte, error) {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
		"_rels/.rels":         `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml":   docxDocument(reportLines(s)),
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func docxDocument(lines []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, line := range lines {
		b.WriteString(`<w:p><w:r><w:t xml:space="preserve">`)
		b.WriteString(html.EscapeString(line))
		b.WriteString(`</w:t></w:r></w:p>`)
	}
	b.WriteString(`<w:sectPr/></w:body></w:document>`)
	return b.String()
}

// pdf emits a small standards-compatible one-page PDF using a built-in Type 1
// font. Non-ASCII glyphs are replaced because embedding customer fonts would
// make the Community binary large; DOCX preserves the original UTF-8 text.
func pdf(s *store.Stats) []byte {
	lines := reportLines(s)
	var content strings.Builder
	content.WriteString("BT /F1 11 Tf 50 760 Td\n")
	for i, line := range lines {
		if i > 0 {
			content.WriteString("0 -15 Td\n")
		}
		content.WriteByte('(')
		content.WriteString(pdfASCII(line))
		content.WriteString(") Tj\n")
	}
	content.WriteString("ET")
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content.String()), content.String()),
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, obj := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

func pdfASCII(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r > 126 {
			b.WriteByte('?')
			continue
		}
		if r == '\\' || r == '(' || r == ')' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
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
	b.WriteString("\n## Отделы\n\n| Отдел | Кол-во |\n|---|---|\n")
	for k, v := range s.ByDepartment {
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
	b.WriteString("\n## Топ тактик\n\n")
	for name, count := range tacticCounts(s.TopSignals) {
		fmt.Fprintf(&b, "- %s — %d\n", name, count)
	}
	fmt.Fprintf(&b, "\nСреднее время анализа: %d мс\nСреднее время реакции: %d мс\n", s.AvgDuration, s.AvgReviewDuration)
	return b.String()
}

// tacticCounts derives stable awareness categories from deterministic signals.
// LLM tactic labels are intentionally not required for this report path.
func tacticCounts(signals []store.NameCount) map[string]int {
	out := map[string]int{}
	for _, signal := range signals {
		name := "other"
		switch {
		case strings.Contains(signal.Name, "credential") || strings.Contains(signal.Name, "sms_code") || strings.Contains(signal.Name, "card_data") || strings.Contains(signal.Name, "login_form"):
			name = "credential_harvesting"
		case strings.Contains(signal.Name, "bec") || strings.Contains(signal.Name, "displayname") || strings.Contains(signal.Name, "replyto"):
			name = "authority_impersonation"
		case strings.Contains(signal.Name, "urgency") || strings.Contains(signal.Name, "threat"):
			name = "urgency_and_fear"
		case strings.Contains(signal.Name, "attachment") || strings.Contains(signal.Name, "macro") || strings.Contains(signal.Name, "archive"):
			name = "malicious_attachment"
		case strings.Contains(signal.Name, "finance") || strings.Contains(signal.Name, "bank_detail"):
			name = "invoice_fraud"
		}
		out[name] += signal.Count
	}
	return out
}

// AwarenessCard is an anonymised training example. It contains no address,
// subject, body, submission ID, or raw evidence.
type AwarenessCard struct {
	Verdict    string   `json:"verdict"`
	AttackType string   `json:"attack_type,omitempty"`
	Brand      string   `json:"brand,omitempty"`
	Score      int      `json:"score"`
	Signals    []string `json:"signals"`
	Lessons    []string `json:"lessons"`
}

// BuildAwarenessCards converts confirmed cases to privacy-safe examples.
func BuildAwarenessCards(submissions []*domain.Submission) []AwarenessCard {
	cards := make([]AwarenessCard, 0, len(submissions))
	for _, sub := range submissions {
		if sub == nil || sub.Status != domain.StatusConfirmedPhish || sub.Result == nil {
			continue
		}
		card := AwarenessCard{Verdict: string(sub.Result.Verdict), Score: sub.Result.Score, AttackType: string(sub.Result.AttackType)}
		if sub.Result.Brand != nil {
			card.Brand = sub.Result.Brand.Name
		}
		seen := map[string]bool{}
		for _, signal := range sub.Result.Signals {
			if seen[signal.ID] {
				continue
			}
			seen[signal.ID] = true
			card.Signals = append(card.Signals, signal.ID)
			card.Lessons = append(card.Lessons, lessonForSignal(signal.ID))
			if len(card.Signals) >= 8 {
				break
			}
		}
		cards = append(cards, card)
	}
	return cards
}

func lessonForSignal(id string) string {
	switch {
	case strings.Contains(id, "credential") || strings.Contains(id, "sms_code") || strings.Contains(id, "card_data") || strings.Contains(id, "login_form"):
		return "Never enter passwords, SMS codes, or card data from an email link."
	case strings.Contains(id, "attachment") || strings.Contains(id, "macro"):
		return "Treat unexpected attachments as unsafe and verify through a known channel."
	case strings.Contains(id, "urgency") || strings.Contains(id, "threat"):
		return "Urgency and threats are pressure tactics; pause and verify independently."
	default:
		return "Inspect the sender, authentication, and destination before acting."
	}
}

// ExportAwareness emits self-contained HTML cards without customer content.
func ExportAwareness(ctx context.Context, st store.Store, orgID string, since time.Time) ([]byte, error) {
	subs, err := st.ListSubmissions(ctx, store.SubmissionFilter{OrgID: orgID, Status: domain.StatusConfirmedPhish, Since: since, Limit: 500})
	if err != nil {
		return nil, err
	}
	return AwarenessHTML(BuildAwarenessCards(subs)), nil
}

// AwarenessHTML renders cards and escapes all dynamic values.
func AwarenessHTML(cards []AwarenessCard) []byte {
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=\"utf-8\"><title>PhishLens awareness cards</title><main><h1>PhishLens: как распознать фишинг</h1>")
	for i, card := range cards {
		fmt.Fprintf(&b, "<article><h2>Пример %d: %s</h2><p>Риск: %d/100", i+1, html.EscapeString(card.Verdict), card.Score)
		if card.AttackType != "" {
			fmt.Fprintf(&b, " · Тип: %s", html.EscapeString(card.AttackType))
		}
		if card.Brand != "" {
			fmt.Fprintf(&b, " · Бренд: %s", html.EscapeString(card.Brand))
		}
		b.WriteString("</p><h3>Что выдало письмо</h3><ul>")
		for _, lesson := range card.Lessons {
			fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(lesson))
		}
		b.WriteString("</ul><p><strong>Сигналы:</strong> ")
		for i, signal := range card.Signals {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "<code>%s</code>", html.EscapeString(signal))
		}
		b.WriteString("</p></article>")
	}
	if len(cards) == 0 {
		b.WriteString("<p>Подтверждённых примеров за период нет.</p>")
	}
	b.WriteString("</main>")
	return []byte(b.String())
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
