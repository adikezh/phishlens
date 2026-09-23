package parse

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/data"
	"github.com/phishlens/phishlens/internal/domain"
)

func demo(t *testing.T, name string) []byte {
	t.Helper()
	b, err := data.FS.ReadFile("demo/" + name)
	require.NoError(t, err)
	return b
}

func TestEMLKaspiPhish(t *testing.T) {
	p := New()
	p.Shorteners = map[string]struct{}{"bit.ly": {}}
	m, err := p.EML(demo(t, "phish_kaspi_01.eml"))
	require.NoError(t, err)

	require.Equal(t, "security@kaspi.kz", m.From.Addr)
	require.Equal(t, "kaspi.kz", m.From.Domain)
	require.Equal(t, "Kaspi Bank", m.From.Display)
	require.Equal(t, "kaspi-secure-login.com", m.ReplyTo.Domain)
	require.Equal(t, "kaspi-secure-login.com", m.ReturnPath.Domain)
	require.Contains(t, m.Subject, "Kaspi будет заблокирован") // RFC 2047 decoded
	require.Equal(t, domain.AuthFail, m.AuthResults.SPF)
	require.Equal(t, domain.AuthNone, m.AuthResults.DKIM)
	require.Equal(t, domain.AuthFail, m.AuthResults.DMARC)
	require.Equal(t, "header", m.AuthResults.Source)
	require.Len(t, m.Received, 1)
	require.Equal(t, "185.220.101.45", m.Received[0].IP)
	require.False(t, m.Received[0].Timestamp.IsZero())
	require.NotEmpty(t, m.HTMLBody)
	require.Contains(t, m.TextBody, "Уважаемый клиент")
	require.Equal(t, "ru", m.Language)

	var mismatch *domain.Link
	for i := range m.Links {
		if m.Links[i].Domain == "kaspi-secure-login.com" && m.Links[i].Text != "" {
			mismatch = &m.Links[i]
		}
	}
	require.NotNil(t, mismatch, "links: %+v", m.Links)
	require.True(t, mismatch.Mismatch)
}

func TestEMLClean(t *testing.T) {
	m, err := New().EML(demo(t, "clean_bank_01.eml"))
	require.NoError(t, err)
	require.True(t, m.AuthResults.AllPass())
	require.Equal(t, "halykbank.kz", m.From.Domain)
	for _, l := range m.Links {
		require.False(t, l.Mismatch, "%+v", l)
	}
}

func TestTextWithHeadersAndPlain(t *testing.T) {
	p := New()
	m, err := p.Text("From: Boss <boss@gmail.com>\nSubject: Срочно\nTo: me@corp.kz\n\nПереведи 100 000 на http://bit.ly/abc сегодня")
	require.NoError(t, err)
	require.Equal(t, "boss@gmail.com", m.From.Addr)
	require.Equal(t, "Срочно", m.Subject)
	require.Len(t, m.Links, 1)

	m, err = p.Text("just a body with https://example.com/login?x=1 and nothing else")
	require.NoError(t, err)
	require.Empty(t, m.From.Addr)
	require.Len(t, m.Links, 1)
	require.Equal(t, "example.com", m.Links[0].Domain)
	require.Equal(t, "en", m.Language)

	_, err = p.Text("   \n")
	require.ErrorIs(t, err, ErrEmpty)
}

func TestMultipartWithAttachment(t *testing.T) {
	raw := "From: a@b.kz\r\nTo: c@d.kz\r\nSubject: inv\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nсм. вложение\r\n" +
		"--XX\r\nContent-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA//8AALgAAAA=\r\n" +
		"--XX--\r\n"
	m, err := New().EML([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, "см. вложение", m.TextBody)
	require.Len(t, m.Attachments, 1)
	a := m.Attachments[0]
	require.Equal(t, "invoice.pdf.exe", a.Name)
	require.Equal(t, "exe", a.Ext)
	require.Len(t, a.SHA256, 64)
	require.Greater(t, a.Size, int64(0))
}

func TestDepthLimit(t *testing.T) {
	p := New()
	p.Limits.MaxDepth = 1
	raw := "From: a@b.kz\r\nContent-Type: multipart/mixed; boundary=\"A\"\r\n\r\n--A\r\nContent-Type: multipart/alternative; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: multipart/related; boundary=\"C\"\r\n\r\n--C\r\nContent-Type: text/plain\r\n\r\nx\r\n--C--\r\n--B--\r\n--A--\r\n"
	_, err := p.EML([]byte(raw))
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestImageWithoutOCR(t *testing.T) {
	// 1x1 PNG
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1F, 0x15, 0xC4, 0x89}
	m, err := New().Image(context.Background(), png)
	require.ErrorIs(t, err, ErrOCRUnavailable)
	require.NotNil(t, m)
	require.Len(t, m.Images, 1)
	require.Equal(t, 1, m.Images[0].Width)
}

func TestDetectLanguage(t *testing.T) {
	require.Equal(t, "ru", DetectLanguage("Срочно подтвердите перевод"))
	require.Equal(t, "en", DetectLanguage("Please verify your account now"))
	require.Equal(t, "kz", DetectLanguage("Шұғыл: деректерді растаңыз, әйтпесе есептік жазба бұғатталады"))
	require.Equal(t, "", DetectLanguage("12345 !!!"))
}

func FuzzEML(f *testing.F) {
	f.Add([]byte("From: a@b.kz\r\nSubject: x\r\n\r\nbody"))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=\"q\"\r\n\r\n--q\r\n\r\n--q--"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = New().EML(data) // must never panic
	})
}
