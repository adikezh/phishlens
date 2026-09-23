// Package i18n renders localised signal explanations and recommendations (F-4.7.5).
// Catalogues live in locales/<lang>.yaml as flat key → fmt template maps.
package i18n

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed locales/*.yaml
var localeFS embed.FS

// Default is the fallback language.
const Default = "ru"

var (
	once      sync.Once
	catalogs  map[string]map[string]string
	loadError error
)

func load() {
	catalogs = map[string]map[string]string{}
	entries, err := fs.ReadDir(localeFS, "locales")
	if err != nil {
		loadError = err
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		b, err := localeFS.ReadFile("locales/" + name)
		if err != nil {
			loadError = err
			return
		}
		m := map[string]string{}
		if err := yaml.Unmarshal(b, &m); err != nil {
			loadError = fmt.Errorf("i18n: %s: %w", name, err)
			return
		}
		catalogs[strings.TrimSuffix(name, ".yaml")] = m
	}
}

// Normalize maps arbitrary language tags to a supported one.
func Normalize(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if i := strings.IndexAny(lang, "-_"); i > 0 {
		lang = lang[:i]
	}
	switch lang {
	case "ru", "en", "kz":
		return lang
	case "kk":
		return "kz"
	}
	return Default
}

// T renders key in lang, falling back to ru → en → the key itself.
func T(lang, key string, args ...any) string {
	once.Do(load)
	for _, l := range []string{Normalize(lang), Default, "en"} {
		if c, ok := catalogs[l]; ok {
			if tmpl, ok := c[key]; ok {
				if len(args) == 0 {
					return tmpl
				}
				return fmt.Sprintf(tmpl, args...)
			}
		}
	}
	return key
}

// Has reports whether key exists in any catalogue.
func Has(key string) bool {
	once.Do(load)
	for _, c := range catalogs {
		if _, ok := c[key]; ok {
			return true
		}
	}
	return false
}

// Err returns a catalogue loading error, if any (checked in tests).
func Err() error {
	once.Do(load)
	return loadError
}
