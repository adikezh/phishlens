package llm

import (
	"fmt"
	"regexp"
	"strings"
)

// Redactor replaces PII with placeholders before text leaves the process (ТЗ §11).
// The placeholder → original map never leaves the process (it is not persisted).
type Redactor struct {
	KeepEmailDomain bool // "[EMAIL_1]@kaspi.kz" keeps the domain, which is itself a signal
}

// Redaction is the result of Redact.
type Redaction struct {
	Text string
	Map  map[string]string // placeholder → original
}

type pattern struct {
	kind  string
	re    *regexp.Regexp
	check func(string) bool
}

var patterns = []pattern{
	{"EMAIL", regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`), nil},
	{"IBAN", regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b`), nil},
	{"CARD", regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`), luhnOK},
	{"IIN", regexp.MustCompile(`\b\d{12}\b`), nil},
	{"PHONE", regexp.MustCompile(`(?:\+?[78]|\+\d{1,3})[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`), nil},
}

// Redact replaces emails, IBANs, card numbers (Luhn-valid), 12-digit IIN/BIN and
// phone numbers with numbered placeholders.
func (r Redactor) Redact(s string) Redaction {
	out := Redaction{Text: s, Map: map[string]string{}}
	counters := map[string]int{}
	seen := map[string]string{} // original → placeholder
	for _, p := range patterns {
		out.Text = p.re.ReplaceAllStringFunc(out.Text, func(m string) string {
			if p.check != nil && !p.check(m) {
				return m
			}
			if ph, ok := seen[m]; ok {
				return ph
			}
			counters[p.kind]++
			ph := fmt.Sprintf("[%s_%d]", p.kind, counters[p.kind])
			if p.kind == "EMAIL" && r.KeepEmailDomain {
				if at := strings.LastIndex(m, "@"); at > 0 {
					ph += m[at:]
				}
			}
			seen[m] = ph
			out.Map[ph] = m
			return ph
		})
	}
	return out
}

// luhnOK validates a digit string with separators using the Luhn checksum.
func luhnOK(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
