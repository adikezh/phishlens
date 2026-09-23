package parse

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/phishlens/phishlens/internal/domain"
)

var (
	reURL = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+`)
	// anchor text that itself looks like a URL or bare domain
	reLooksLikeURL = regexp.MustCompile(`(?i)^(?:https?://)?(?:www\.)?[\p{L}\p{N}\-]+(?:\.[\p{L}\p{N}\-]+)+(?:[:/?#].*)?$`)
)

// ExtractHTML returns <a href> links (with anchor text) and the visible text of an
// HTML body. Script/style contents are skipped; hidden-text detection is done by
// the content.hidden_text signal on the raw HTML.
func ExtractHTML(src string) ([]domain.Link, string) {
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		return nil, stripTags(src)
	}
	var links []domain.Link
	var text strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "head", "title":
				return
			case "a", "area":
				if href := attr(n, "href"); href != "" {
					links = append(links, domain.Link{Href: strings.TrimSpace(href), Text: strings.TrimSpace(innerText(n))})
				}
			case "form":
				if action := attr(n, "action"); action != "" {
					links = append(links, domain.Link{Href: strings.TrimSpace(action), Text: "form action"})
				}
			case "br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "td":
				text.WriteByte('\n')
			}
		}
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
			text.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links, normalizeSpace(text.String())
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func innerText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		if n.Type == html.ElementNode && n.Data == "img" {
			if alt := attr(n, "alt"); alt != "" {
				b.WriteString(alt)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

var reTags = regexp.MustCompile(`(?s)<[^>]*>`)

func stripTags(s string) string {
	return normalizeSpace(reTags.ReplaceAllString(s, " "))
}

func normalizeSpace(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		l = strings.Join(strings.Fields(l), " ")
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// ExtractURLs finds http(s):// and www. URLs in plain text.
func ExtractURLs(text string) []string {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range reURL.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;:!?»\"'")
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
