package parse

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/phishlens/phishlens/internal/domain"
)

var (
	pdfURLPattern  = regexp.MustCompile(`(?i)https?://[^\s()<>{}\[\]"']+`)
	pdfLiteralText = regexp.MustCompile(`\(([^()\r\n]{1,500})\)`)
	pdfPagePattern = []byte(`/Type /Page`)
)

// PDF performs a bounded static scan. It extracts visible-ish literal text
// and URLs and flags active PDF features, but never renders, launches actions,
// follows URLs, or writes embedded files to disk.
func (p *Parser) PDF(data []byte) (*domain.ParsedMail, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, fmt.Errorf("parse pdf: missing PDF header")
	}
	if int64(len(data)) > p.Limits.MaxBodyBytes*6 && p.Limits.MaxBodyBytes > 0 {
		return nil, fmt.Errorf("%w: pdf exceeds parser limit", ErrTooLarge)
	}
	lower := bytes.ToLower(data)
	info := &domain.PDFInfo{
		Pages:         bytes.Count(data, pdfPagePattern),
		HasJavaScript: bytes.Contains(lower, []byte("/javascript")) || bytes.Contains(lower, []byte("/js ")),
		HasOpenAction: bytes.Contains(lower, []byte("/openaction")),
		HasAutoAction: bytes.Contains(lower, []byte("/aa")),
		HasForms:      bytes.Contains(lower, []byte("/acroform")) || bytes.Contains(lower, []byte("/xfa")),
		HasEmbedded:   bytes.Contains(lower, []byte("/embeddedfile")) || bytes.Contains(lower, []byte("/filespec")),
	}
	seen := map[string]struct{}{}
	var text strings.Builder
	for _, match := range pdfLiteralText.FindAllSubmatch(data, 400) {
		part := strings.TrimSpace(string(match[1]))
		if part == "" || !hasLetter(part) {
			continue
		}
		if text.Len() > 0 {
			text.WriteByte(' ')
		}
		text.WriteString(part)
	}
	for _, raw := range pdfURLPattern.FindAll(data, p.Limits.MaxLinks) {
		u := strings.TrimRight(string(raw), ".,;:!?")
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		info.URLs = append(info.URLs, u)
	}
	pm := &domain.ParsedMail{Headers: map[string][]string{}, TextBody: text.String(), PDF: info}
	for _, u := range info.URLs {
		pm.Links = append(pm.Links, domain.Link{Href: u, Text: u})
	}
	p.finish(pm)
	return pm, nil
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
