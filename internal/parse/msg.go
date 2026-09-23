package parse

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/mail"
	"net/textproto"
	"strings"
	"unicode/utf16"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/richardlehane/mscfb"
)

// cfbMagic is the OLE2 compound-file signature.
var cfbMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// MSG parses the common Outlook .msg MAPI properties without executing or
// extracting embedded files. Unsupported or private MAPI properties are
// ignored; the normalized result still goes through the same link, language,
// and signal pipeline as EML.
func (p *Parser) MSG(data []byte) (*domain.ParsedMail, error) {
	if len(data) < 8 || !bytes.Equal(data[:8], cfbMagic) {
		return nil, errors.New("parse msg: not an OLE2 compound file")
	}
	r, err := mscfb.New(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("parse msg: invalid OLE2 compound file")
	}

	root := map[string][]byte{}
	recipients := map[string]map[string][]byte{}
	attachments := map[string]map[string][]byte{}
	for f, nextErr := r.Next(); nextErr == nil && f != nil; f, nextErr = r.Next() {
		limit := p.Limits.MaxBodyBytes
		if strings.HasPrefix(firstPath(f.Path), "__attach_version1.0_") {
			limit = p.Limits.MaxAttachment
		}
		if limit <= 0 {
			limit = DefaultLimits.MaxAttachment
		}
		if f.Size > limit {
			return nil, ErrTooLarge
		}
		b, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil {
			return nil, errors.New("parse msg: cannot read stream")
		}
		if int64(len(b)) > limit {
			return nil, ErrTooLarge
		}
		key := strings.ToLower(f.Name)
		switch path := firstPath(f.Path); {
		case strings.HasPrefix(path, "__recip_version1.0_"):
			if recipients[path] == nil {
				recipients[path] = map[string][]byte{}
			}
			recipients[path][key] = b
		case strings.HasPrefix(path, "__attach_version1.0_"):
			if attachments[path] == nil {
				attachments[path] = map[string][]byte{}
			}
			attachments[path][key] = b
		case len(f.Path) == 0:
			root[key] = b
		}
	}

	pm := &domain.ParsedMail{Headers: map[string][]string{}}
	pm.Subject = msgText(root, "__substg1.0_0037001f", "__substg1.0_0037001e")
	pm.From = domain.Address{
		Display: msgText(root, "__substg1.0_0c1a001f", "__substg1.0_0c1a001e"),
		Addr:    msgText(root, "__substg1.0_0c1f001f", "__substg1.0_0c1f001e"),
	}
	pm.From = ParseAddress(strings.TrimSpace(pm.From.Display + " <" + pm.From.Addr + ">"))
	pm.TextBody = msgText(root, "__substg1.0_1000001f", "__substg1.0_1000001e")
	pm.HTMLBody = msgText(root, "__substg1.0_1013001f", "__substg1.0_1013001e")

	if raw := msgText(root, "__substg1.0_007d001f", "__substg1.0_007d001e"); raw != "" {
		applyTransportHeaders(pm, raw)
	}
	for _, props := range recipients {
		addr := ParseAddress(strings.TrimSpace(msgText(props, "__substg1.0_3001001f", "__substg1.0_3001001e") + " <" + msgText(props, "__substg1.0_3003001f", "__substg1.0_3003001e") + ">"))
		if addr.IsZero() {
			continue
		}
		// 0x00000002 is CC, 0x00000003 is BCC; both are intentionally
		// represented in the normalized recipient list only when visible.
		typ := msgDWORD(props["__substg1.0_0c150003"])
		if typ != 2 && typ != 3 {
			pm.To = append(pm.To, addr)
		} else if typ == 2 {
			pm.CC = append(pm.CC, addr)
		}
	}
	for _, props := range attachments {
		name := msgText(props, "__substg1.0_3707001f", "__substg1.0_3707001e")
		if name == "" {
			name = msgText(props, "__substg1.0_3001001f", "__substg1.0_3001001e")
		}
		content := props["__substg1.0_37010102"]
		if len(content) == 0 {
			continue
		}
		mime := msgText(props, "__substg1.0_370e001f", "__substg1.0_370e001e")
		pm.Attachments = append(pm.Attachments, p.attachmentFrom(name, mime, content))
	}
	p.finish(pm)
	return pm, nil
}

func firstPath(path []string) string {
	if len(path) == 0 {
		return ""
	}
	return strings.ToLower(path[0])
}

func msgText(props map[string][]byte, utf16Key, ansiKey string) string {
	if b := props[utf16Key]; len(b) > 0 {
		if len(b)%2 == 1 {
			b = b[:len(b)-1]
		}
		u := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
		}
		return strings.TrimRight(string(utf16.Decode(u)), "\x00")
	}
	return strings.TrimRight(string(props[ansiKey]), "\x00")
}

func msgDWORD(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b[:4])
}

func applyTransportHeaders(pm *domain.ParsedMail, raw string) {
	h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(raw))).ReadMIMEHeader()
	if err != nil {
		return
	}
	for key, values := range h {
		pm.Headers[key] = append([]string(nil), values...)
	}
	if pm.From.IsZero() {
		pm.From = ParseAddress(h.Get("From"))
	}
	if pm.Subject == "" {
		pm.Subject = DecodeHeader(h.Get("Subject"))
	}
	pm.ReplyTo = ParseAddress(h.Get("Reply-To"))
	pm.ReturnPath = ParseAddress(h.Get("Return-Path"))
	pm.To = append(pm.To, ParseAddressList(h.Get("To"))...)
	pm.CC = append(pm.CC, ParseAddressList(h.Get("Cc"))...)
	pm.Received = ParseReceived(h.Values("Received"))
	pm.AuthResults = ParseAuthResults(strings.Join(h.Values("Authentication-Results"), "; "))
	if date, err := mail.ParseDate(h.Get("Date")); err == nil {
		pm.Date = date
	}
}
