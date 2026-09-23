package parse

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html/charset"

	"github.com/phishlens/phishlens/internal/domain"
)

// wordDecoder decodes RFC 2047 headers, including common Cyrillic legacy
// encodings used by Russian mail clients.
var wordDecoder = mime.WordDecoder{
	CharsetReader: charset.NewReaderLabel,
}

var (
	reBracketIP = regexp.MustCompile(`\[(\d{1,3}(?:\.\d{1,3}){3})\]`)
	reAnyIP     = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	reRcvFrom   = regexp.MustCompile(`(?i)\bfrom\s+([^\s(;]+)`)
	reRcvBy     = regexp.MustCompile(`(?i)\bby\s+([^\s(;]+)`)
	reAuthRes   = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc|arc)=([a-z]+)`)
	reAngleAddr = regexp.MustCompile(`<([^<>@\s]+@[^<>@\s]+)>`)
	reBareAddr  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

// EML parses an RFC 5322 message.
func (p *Parser) EML(data []byte) (*domain.ParsedMail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse eml: %w", err)
	}
	pm := &domain.ParsedMail{Raw: append([]byte(nil), data...), Headers: map[string][]string{}}
	for k, v := range msg.Header {
		pm.Headers[k] = v
	}
	pm.From = ParseAddress(msg.Header.Get("From"))
	pm.ReplyTo = ParseAddress(msg.Header.Get("Reply-To"))
	pm.ReturnPath = ParseAddress(msg.Header.Get("Return-Path"))
	pm.To = ParseAddressList(msg.Header.Get("To"))
	pm.CC = ParseAddressList(msg.Header.Get("Cc"))
	pm.Subject = DecodeHeader(msg.Header.Get("Subject"))
	if d, err := msg.Header.Date(); err == nil {
		pm.Date = d
	}
	pm.Received = ParseReceived(msg.Header["Received"])
	pm.AuthResults = ParseAuthResults(strings.Join(msg.Header["Authentication-Results"], "; "))

	parts := 0
	if err := p.walkBody(pm, textproto.MIMEHeader(msg.Header), msg.Body, 0, &parts); err != nil {
		return nil, err
	}
	p.finish(pm)
	return pm, nil
}

// walkBody recursively collects text, HTML, images and attachments.
func (p *Parser) walkBody(pm *domain.ParsedMail, h textproto.MIMEHeader, body io.Reader, depth int, parts *int) error {
	if depth > p.Limits.MaxDepth {
		return fmt.Errorf("%w: MIME nesting deeper than %d", ErrTooLarge, p.Limits.MaxDepth)
	}
	*parts++
	if *parts > p.Limits.MaxParts {
		return fmt.Errorf("%w: more than %d MIME parts", ErrTooLarge, p.Limits.MaxParts)
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType, params = "text/plain", map[string]string{}
	}
	mediaType = strings.ToLower(mediaType)

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return nil
		}
		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				// tolerate truncated multiparts: keep what we have
				return nil
			}
			if err := p.walkBody(pm, part.Header, part, depth+1, parts); err != nil {
				return err
			}
		}
	}

	limit := p.Limits.MaxBodyBytes
	if !strings.HasPrefix(mediaType, "text/") {
		limit = p.Limits.MaxAttachment
	}
	content, err := decodeTransfer(h.Get("Content-Transfer-Encoding"), io.LimitReader(body, limit+1))
	if err != nil {
		return fmt.Errorf("parse eml: decode part: %w", err)
	}
	if int64(len(content)) > limit {
		return fmt.Errorf("%w: part exceeds %d bytes", ErrTooLarge, limit)
	}

	disposition, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	filename := DecodeHeader(dparams["filename"])
	if filename == "" {
		filename = DecodeHeader(params["name"])
	}
	isAttachment := strings.EqualFold(disposition, "attachment") ||
		(filename != "" && !strings.HasPrefix(mediaType, "text/") && !strings.HasPrefix(mediaType, "image/"))

	switch {
	case isAttachment:
		pm.Attachments = append(pm.Attachments, p.attachmentFrom(filename, mediaType, content))
	case mediaType == "text/plain":
		pm.TextBody = appendText(pm.TextBody, string(decodeText(content, params["charset"])))
	case mediaType == "text/html":
		pm.HTMLBody = appendText(pm.HTMLBody, string(decodeText(content, params["charset"])))
	case strings.HasPrefix(mediaType, "image/"):
		img := imageFrom(content, mediaType, p.Limits.MaxImagePixels)
		img.ContentID = strings.Trim(h.Get("Content-ID"), "<>")
		pm.Images = append(pm.Images, img)
	case mediaType == "message/rfc822":
		// forwarded message as attachment: parse nested headers/body into the same mail
		if nested, err := mail.ReadMessage(bytes.NewReader(content)); err == nil {
			if pm.Subject == "" {
				pm.Subject = DecodeHeader(nested.Header.Get("Subject"))
			}
			return p.walkBody(pm, textproto.MIMEHeader(nested.Header), nested.Body, depth+1, parts)
		}
		pm.Attachments = append(pm.Attachments, p.attachmentFrom(filename, mediaType, content))
	default:
		if filename == "" {
			filename = "unnamed." + extFromMIME(mediaType)
		}
		pm.Attachments = append(pm.Attachments, p.attachmentFrom(filename, mediaType, content))
	}
	return nil
}

func decodeText(content []byte, label string) []byte {
	if strings.TrimSpace(label) == "" {
		return content
	}
	reader, err := charset.NewReaderLabel(label, bytes.NewReader(content))
	if err != nil {
		return content
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return content
	}
	return decoded
}

func appendText(dst, add string) string {
	add = strings.TrimSpace(add)
	if add == "" {
		return dst
	}
	if dst == "" {
		return add
	}
	return dst + "\n\n" + add
}

func decodeTransfer(enc string, r io.Reader) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, &b64Cleaner{r: r}))
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(r))
	default:
		return io.ReadAll(r)
	}
}

// b64Cleaner strips whitespace so lenient base64 bodies decode.
type b64Cleaner struct{ r io.Reader }

func (c *b64Cleaner) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	w := 0
	for i := 0; i < n; i++ {
		switch p[i] {
		case '\r', '\n', ' ', '\t':
			continue
		}
		p[w] = p[i]
		w++
	}
	if w == 0 && n > 0 && err == nil {
		return c.Read(p)
	}
	return w, err
}

// DecodeHeader decodes RFC 2047 encoded words.
func DecodeHeader(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if d, err := wordDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

// ParseAddress parses a single mailbox, tolerating malformed input.
func ParseAddress(s string) domain.Address {
	s = DecodeHeader(s)
	if s == "" {
		return domain.Address{}
	}
	if a, err := mail.ParseAddress(s); err == nil {
		return mkAddress(a.Name, a.Address)
	}
	if m := reAngleAddr.FindStringSubmatch(s); m != nil {
		name := strings.TrimSpace(strings.Trim(strings.Split(s, "<")[0], `" `))
		return mkAddress(name, m[1])
	}
	if m := reBareAddr.FindString(s); m != "" {
		return mkAddress("", m)
	}
	return domain.Address{Display: s}
}

// ParseAddressList parses a comma-separated list, tolerating malformed entries.
func ParseAddressList(s string) []domain.Address {
	s = DecodeHeader(s)
	if s == "" {
		return nil
	}
	if list, err := mail.ParseAddressList(s); err == nil {
		out := make([]domain.Address, 0, len(list))
		for _, a := range list {
			out = append(out, mkAddress(a.Name, a.Address))
		}
		return out
	}
	var out []domain.Address
	for _, part := range strings.Split(s, ",") {
		if a := ParseAddress(part); !a.IsZero() {
			out = append(out, a)
		}
	}
	return out
}

func mkAddress(name, addr string) domain.Address {
	addr = strings.ToLower(strings.TrimSpace(addr))
	a := domain.Address{Display: strings.TrimSpace(name), Addr: addr}
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		a.Domain = addr[i+1:]
	}
	return a
}

// ParseReceived extracts host/IP/timestamp from Received: headers (top = last hop).
func ParseReceived(lines []string) []domain.ReceivedHop {
	hops := make([]domain.ReceivedHop, 0, len(lines))
	for _, raw := range lines {
		raw = strings.Join(strings.Fields(raw), " ")
		hop := domain.ReceivedHop{Raw: raw}
		if m := reRcvFrom.FindStringSubmatch(raw); m != nil {
			hop.From = m[1]
		}
		if m := reRcvBy.FindStringSubmatch(raw); m != nil {
			hop.By = m[1]
		}
		if m := reBracketIP.FindStringSubmatch(raw); m != nil {
			hop.IP = m[1]
		} else if m := reAnyIP.FindStringSubmatch(raw); m != nil {
			hop.IP = m[1]
		}
		if i := strings.LastIndex(raw, ";"); i >= 0 {
			if t, err := mail.ParseDate(strings.TrimSpace(raw[i+1:])); err == nil {
				hop.Timestamp = t
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

// ParseAuthResults reads spf=/dkim=/dmarc=/arc= from an Authentication-Results header.
func ParseAuthResults(s string) domain.AuthResults {
	ar := domain.AuthResults{Raw: strings.TrimSpace(s)}
	if ar.Raw == "" {
		return ar
	}
	ar.Source = "header"
	for _, m := range reAuthRes.FindAllStringSubmatch(s, -1) {
		res := domain.AuthResult(strings.ToLower(m[2]))
		switch strings.ToLower(m[1]) {
		case "spf":
			if ar.SPF == "" {
				ar.SPF = res
			}
		case "dkim":
			if ar.DKIM == "" {
				ar.DKIM = res
			}
		case "dmarc":
			if ar.DMARC == "" {
				ar.DMARC = res
			}
		case "arc":
			if ar.ARC == "" {
				ar.ARC = res
			}
		}
	}
	return ar
}

// finish derives links, language and text fallbacks after the body walk.
func (p *Parser) finish(pm *domain.ParsedMail) {
	if pm.HTMLBody != "" {
		links, text := ExtractHTML(pm.HTMLBody)
		pm.Links = append(pm.Links, links...)
		if pm.TextBody == "" {
			pm.TextBody = text
		}
	}
	for _, u := range ExtractURLs(pm.TextBody) {
		pm.Links = append(pm.Links, domain.Link{Href: u})
	}
	pm.Links = p.classifyLinks(pm.Links)
	pm.Language = DetectLanguage(pm.Subject + "\n" + pm.TextBody)
	if pm.Date.IsZero() && len(pm.Received) > 0 {
		pm.Date = pm.Received[0].Timestamp
	}
}

// FirstReceivedTime returns the timestamp of the earliest hop (closest to the sender).
func FirstReceivedTime(hops []domain.ReceivedHop) time.Time {
	for i := len(hops) - 1; i >= 0; i-- {
		if !hops[i].Timestamp.IsZero() {
			return hops[i].Timestamp
		}
	}
	return time.Time{}
}
