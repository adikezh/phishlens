package parse

import (
	"context"
	"testing"
)

func FuzzParserText(f *testing.F) {
	f.Add("Subject: hello\n\nhttps://example.com")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = New().Parse(context.Background(), "text", []byte(input))
	})
}

func FuzzExtractHTML(f *testing.F) {
	f.Add("<a href='https://example.com'>example</a>")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ExtractHTML(input)
		_ = ExtractURLs(input)
	})
}

func FuzzAttachmentListing(f *testing.F) {
	f.Add("archive.zip", "application/zip", []byte("not a zip"))
	f.Add("page.html", "text/html", []byte("<script>alert(1)</script>"))
	f.Fuzz(func(t *testing.T, name, mime string, content []byte) {
		p := New()
		p.Limits.MaxArchiveNames = 10
		_ = p.attachmentFrom(name, mime, content)
	})
}
