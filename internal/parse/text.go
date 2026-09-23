package parse

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/phishlens/phishlens/internal/domain"
)

// reHeaderBlock detects a pasted message that still carries its headers.
var reHeaderBlock = regexp.MustCompile(`(?im)^(From|Received|Return-Path|Subject|To|Date|Message-ID|MIME-Version|Authentication-Results|Reply-To):\s`)

// Text handles raw pasted text: if it looks like a full message with headers it
// is parsed as EML, otherwise it becomes a body-only ParsedMail.
func (p *Parser) Text(s string) (*domain.ParsedMail, error) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimLeft(s, "\xEF\xBB\xBF \n")
	if s == "" {
		return nil, ErrEmpty
	}
	if len(reHeaderBlock.FindAllStringIndex(firstLines(s, 30), -1)) >= 2 {
		if pm, err := p.EML([]byte(strings.ReplaceAll(s, "\n", "\r\n"))); err == nil {
			return pm, nil
		}
	}
	pm := &domain.ParsedMail{Headers: map[string][]string{}}
	// forwarded-message conventions: "От: X <x@y>" / "From: ..." inside the body
	if m := reInlineFrom.FindStringSubmatch(s); m != nil {
		pm.From = ParseAddress(m[2])
	}
	if m := reInlineSubject.FindStringSubmatch(s); m != nil {
		pm.Subject = strings.TrimSpace(m[2])
	}
	pm.TextBody = strings.TrimSpace(s)
	p.finish(pm)
	return pm, nil
}

var (
	reInlineFrom    = regexp.MustCompile(`(?im)^(From|От|Кімнен):\s*(.+)$`)
	reInlineSubject = regexp.MustCompile(`(?im)^(Subject|Тема|Тақырып):\s*(.+)$`)
)

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// DetectLanguage is a cheap script-based heuristic: kz (Kazakh-specific Cyrillic
// letters), ru (Cyrillic), en (Latin), "" (unknown). TODO: proper n-gram model.
func DetectLanguage(s string) string {
	var cyr, lat, kz int
	for _, r := range s {
		switch {
		case strings.ContainsRune("әғқңөұүһіӘҒҚҢӨҰҮҺІ", r):
			kz++
			cyr++
		case unicode.Is(unicode.Cyrillic, r):
			cyr++
		case unicode.Is(unicode.Latin, r):
			lat++
		}
	}
	switch {
	case cyr == 0 && lat == 0:
		return ""
	case kz > 0 && kz*40 >= cyr:
		return "kz"
	case cyr >= lat:
		return "ru"
	default:
		return "en"
	}
}
