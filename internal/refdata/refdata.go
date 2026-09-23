// Package refdata loads reference lists (shorteners, risky TLDs, free-mail domains,
// keyword dictionaries, homoglyph table, dangerous extensions). Files are looked up
// on disk under dir first and fall back to the embedded copies in package data.
package refdata

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Languages supported by dictionaries and explanations.
var Languages = []string{"ru", "en", "kz"}

// KeywordSet is one language's dictionary (data/keywords/<lang>.yaml).
type KeywordSet struct {
	Urgency    []string `yaml:"urgency"`
	Threat     []string `yaml:"threat"`
	Finance    []string `yaml:"finance"`
	Credential []string `yaml:"credential"`
	BEC        []string `yaml:"bec"`
}

// Data is the loaded reference set shared by all signals.
type Data struct {
	Shorteners      map[string]struct{}
	RiskyTLDs       map[string]int // tld → risk 0..15
	FreeMailDomains map[string]struct{}
	DangerousExts   map[string]struct{}
	Keywords        map[string]*KeywordSet // lang → dictionary
	Homoglyphs      map[rune]rune
}

// Load reads every reference file. dir may be empty (embedded only).
func Load(fsys fs.FS, dir string) (*Data, error) {
	d := &Data{Keywords: map[string]*KeywordSet{}, Homoglyphs: map[rune]rune{}}
	var err error
	if d.Shorteners, err = loadSet(fsys, dir, "shorteners.txt"); err != nil {
		return nil, err
	}
	if d.FreeMailDomains, err = loadSet(fsys, dir, "free_mail_domains.txt"); err != nil {
		return nil, err
	}
	if d.DangerousExts, err = loadSet(fsys, dir, "dangerous_extensions.txt"); err != nil {
		return nil, err
	}
	var tlds struct {
		TLDs map[string]int `yaml:"tlds"`
	}
	if err = LoadYAML(fsys, dir, "risky_tlds.yaml", &tlds); err != nil {
		return nil, err
	}
	d.RiskyTLDs = tlds.TLDs
	var hg struct {
		Map map[string]string `yaml:"map"`
	}
	if err = LoadYAML(fsys, dir, "homoglyphs.yaml", &hg); err != nil {
		return nil, err
	}
	for k, v := range hg.Map {
		kr, vr := []rune(k), []rune(v)
		if len(kr) == 1 && len(vr) == 1 {
			d.Homoglyphs[kr[0]] = vr[0]
		}
	}
	for _, lang := range Languages {
		ks := &KeywordSet{}
		if err = LoadYAML(fsys, dir, path.Join("keywords", lang+".yaml"), ks); err != nil {
			return nil, err
		}
		d.Keywords[lang] = ks
	}
	return d, nil
}

// Open returns name from dir on disk if present, otherwise from fsys.
func Open(fsys fs.FS, dir, name string) (io.ReadCloser, error) {
	if dir != "" {
		if f, err := os.Open(filepath.Join(dir, filepath.FromSlash(name))); err == nil {
			return f, nil
		}
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("refdata: open %s: %w", name, err)
	}
	return f, nil
}

// OpenPath opens an explicit path, falling back to the embedded fallback file when
// the path is empty or missing (lets config point at data/brands.yaml while the
// binary still works on its own).
func OpenPath(fsys fs.FS, p, fallback string) (io.ReadCloser, error) {
	if p != "" {
		if f, err := os.Open(p); err == nil {
			return f, nil
		}
	}
	if fallback == "" && p != "" {
		fallback = path.Base(filepath.ToSlash(p))
	}
	return Open(fsys, "", fallback)
}

// LoadYAML decodes name into out.
func LoadYAML(fsys fs.FS, dir, name string, out any) error {
	f, err := Open(fsys, dir, name)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(out); err != nil {
		return fmt.Errorf("refdata: decode %s: %w", name, err)
	}
	return nil
}

func loadSet(fsys fs.FS, dir, name string) (map[string]struct{}, error) {
	f, err := Open(fsys, dir, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	return set, sc.Err()
}

// Keywords returns the dictionary for lang, falling back to ru then en.
func (d *Data) KeywordsFor(lang string) *KeywordSet {
	if ks, ok := d.Keywords[lang]; ok {
		return ks
	}
	if ks, ok := d.Keywords["ru"]; ok {
		return ks
	}
	return d.Keywords["en"]
}

// AllKeywords returns dictionaries for every loaded language (content signals scan all of them).
func (d *Data) AllKeywords() []*KeywordSet {
	out := make([]*KeywordSet, 0, len(d.Keywords))
	for _, lang := range Languages {
		if ks, ok := d.Keywords[lang]; ok {
			out = append(out, ks)
		}
	}
	return out
}
