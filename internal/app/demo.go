package app

import (
	"io/fs"
	"sort"
	"strings"

	"github.com/phishlens/phishlens/data"
)

// Demo is a built-in example (F-4.7.3).
type Demo struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	File  string `json:"file"`
}

var demoTitles = map[string]string{
	"phish_kaspi_01": "Фишинг «Kaspi»: подмена отправителя и ссылки",
	"bec_ceo_01":     "BEC: «срочный платёж» от директора с Gmail",
	"clean_bank_01":  "Чистое письмо от банка с валидными SPF/DKIM/DMARC",
}

// Demos lists embedded demo emails.
func Demos() []Demo {
	entries, err := fs.ReadDir(data.FS, "demo")
	if err != nil {
		return nil
	}
	var out []Demo
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".eml")
		title := demoTitles[name]
		if title == "" {
			title = name
		}
		out = append(out, Demo{Name: name, Title: title, File: "demo/" + e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DemoBytes returns the raw .eml of a demo by name.
func DemoBytes(name string) ([]byte, bool) {
	for _, d := range Demos() {
		if d.Name == name {
			b, err := fs.ReadFile(data.FS, d.File)
			return b, err == nil
		}
	}
	return nil, false
}
