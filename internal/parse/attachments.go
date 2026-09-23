package parse

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
)

var (
	archiveExts = map[string]bool{"zip": true, "rar": true, "7z": true, "gz": true, "tgz": true, "tar": true, "iso": true, "img": true, "cab": true, "arj": true}
	macroExts   = map[string]bool{"docm": true, "xlsm": true, "pptm": true, "dotm": true, "xltm": true, "potm": true}
	ooxmlExts   = map[string]bool{"docx": true, "xlsx": true, "pptx": true, "docm": true, "xlsm": true, "pptm": true, "dotm": true, "xltm": true}
	reScriptTag = regexp.MustCompile(`(?i)<script\b|<form\b|<iframe\b|javascript:`)
)

// attachmentFrom builds metadata: hash, extension, archive listing (zip only —
// rar/7z listing TODO A-02), OOXML macro detection, HTML active content.
// The content is never written to disk or executed.
func (p *Parser) attachmentFrom(name, mime string, content []byte) domain.Attachment {
	sum := sha256.Sum256(content)
	a := domain.Attachment{
		Name:   name,
		MIME:   mime,
		Size:   int64(len(content)),
		SHA256: hex.EncodeToString(sum[:]),
		Ext:    Ext(name),
	}
	a.IsArchive = archiveExts[a.Ext]
	switch {
	case a.Ext == "zip" || strings.Contains(mime, "zip") || ooxmlExts[a.Ext]:
		names, encrypted := listZip(content, p.Limits.MaxArchiveNames)
		if ooxmlExts[a.Ext] {
			for _, n := range names {
				if strings.EqualFold(path.Base(n), "vbaProject.bin") {
					a.MacroDetected = true
				}
			}
		} else {
			a.NestedNames = names
			a.PasswordProtected = encrypted
		}
	case a.Ext == "html" || a.Ext == "htm" || a.Ext == "shtml" || strings.Contains(mime, "html"):
		a.HasActiveContent = reScriptTag.Match(content)
	}
	if macroExts[a.Ext] {
		a.MacroDetected = true
	}
	// TODO(A-03): legacy OLE .doc/.xls — richardlehane/mscfb + VBA stream search.
	// PDF static analysis is handled by ParsePDF; this path only dispatches
	// generic attachment metadata and must not render or execute PDF content.
	return a
}

// Ext returns the lowercase final extension without the dot.
func Ext(name string) string {
	e := strings.ToLower(strings.TrimPrefix(path.Ext(strings.TrimSpace(name)), "."))
	return e
}

// listZip lists entry names without extracting; encrypted is true when any entry
// has the encryption flag set (A-02).
func listZip(content []byte, maxNames int) (names []string, encrypted bool) {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, false
	}
	for i, f := range zr.File {
		if i >= maxNames {
			break
		}
		names = append(names, f.Name)
		if f.Flags&0x1 != 0 {
			encrypted = true
		}
	}
	return names, encrypted
}

func extFromMIME(mime string) string {
	if i := strings.LastIndex(mime, "/"); i >= 0 && i < len(mime)-1 {
		return mime[i+1:]
	}
	return "bin"
}
