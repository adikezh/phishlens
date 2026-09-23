package llm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"text/template"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/i18n"
	"github.com/phishlens/phishlens/internal/refdata"
)

// PromptVersion is part of the cache key so prompt changes invalidate cached explanations.
const PromptVersion = "explain_v1"

const userSeparator = "---USER---"

// PromptData is what templates see.
type PromptData struct {
	LangName    string
	Signals     []domain.Signal
	Brand       string
	Score       int
	Subject     string
	From        string
	ReplyTo     string
	Links       string
	Attachments string
	Body        string
}

// Prompts loads and renders explain_v1.<lang>.txt (system ---USER--- user).
type Prompts struct {
	fsys fs.FS
	dir  string
	tmpl map[string]*template.Template
}

// NewPrompts prepares templates for every supported language (kz falls back to ru).
func NewPrompts(fsys fs.FS, dir string) (*Prompts, error) {
	p := &Prompts{fsys: fsys, dir: dir, tmpl: map[string]*template.Template{}}
	for _, lang := range refdata.Languages {
		name := PromptVersion + "." + lang + ".txt"
		f, err := refdata.Open(fsys, dir, name)
		if err != nil {
			if lang == "ru" {
				return nil, err
			}
			continue
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		t, err := template.New(name).Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("llm: prompt %s: %w", name, err)
		}
		p.tmpl[lang] = t
	}
	return p, nil
}

// Render produces system and user prompts plus a hash of the rendered pair.
func (p *Prompts) Render(lang string, d PromptData) (system, user, hash string, err error) {
	lang = i18n.Normalize(lang)
	t, ok := p.tmpl[lang]
	if !ok {
		t = p.tmpl["ru"]
	}
	if d.LangName == "" {
		d.LangName = i18n.T(lang, "lang.name")
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", "", "", fmt.Errorf("llm: render prompt: %w", err)
	}
	parts := strings.SplitN(buf.String(), userSeparator, 2)
	system = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		user = strings.TrimSpace(parts[1])
	} else {
		user, system = system, ""
	}
	sum := sha256.Sum256([]byte(system + "\n" + user))
	return system, user, hex.EncodeToString(sum[:8]), nil
}
