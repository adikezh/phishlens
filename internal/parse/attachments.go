package parse

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/richardlehane/mscfb"
)

var (
	archiveExts   = map[string]bool{"zip": true, "rar": true, "7z": true, "gz": true, "tgz": true, "tar": true, "iso": true, "img": true, "cab": true, "arj": true}
	macroExts     = map[string]bool{"docm": true, "xlsm": true, "pptm": true, "dotm": true, "xltm": true, "potm": true}
	ooxmlExts     = map[string]bool{"docx": true, "xlsx": true, "pptx": true, "docm": true, "xlsm": true, "pptm": true, "dotm": true, "xltm": true}
	oleOfficeExts = map[string]bool{"doc": true, "xls": true, "ppt": true, "dot": true, "xlt": true, "pot": true}
	reScriptTag   = regexp.MustCompile(`(?i)<script\b|<form\b|<iframe\b|javascript:`)
)

// attachmentFrom builds metadata: hash, extension, archive listing, OOXML macro
// detection, and HTML active content. Archive contents are never extracted to
// disk or executed.
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
	case a.Ext == "rar":
		a.NestedNames, a.PasswordProtected = listRAR(content, p.Limits.MaxArchiveNames)
	case a.Ext == "7z":
		a.NestedNames, a.PasswordProtected = list7z(content, p.Limits.MaxArchiveNames)
	case oleOfficeExts[a.Ext]:
		a.MacroDetected = oleHasVBA(content)
	case a.Ext == "html" || a.Ext == "htm" || a.Ext == "shtml" || strings.Contains(mime, "html"):
		a.HasActiveContent = reScriptTag.Match(content)
	}
	if macroExts[a.Ext] {
		a.MacroDetected = true
	}
	// PDF static analysis is handled by ParsePDF; this path only dispatches
	// generic attachment metadata and must not render or execute PDF content.
	return a
}

// oleHasVBA inspects only the compound-file directory tree. It does not open
// or execute a stream, so legacy Office macro detection stays metadata-only.
func oleHasVBA(content []byte) bool {
	if len(content) < len(cfbMagic) || !bytes.Equal(content[:len(cfbMagic)], cfbMagic) {
		return false
	}
	r, err := mscfb.New(bytes.NewReader(content))
	if err != nil {
		return false
	}
	for f, nextErr := r.Next(); nextErr == nil && f != nil; f, nextErr = r.Next() {
		for _, component := range append([]string{f.Name}, f.Path...) {
			name := strings.ToLower(component)
			if name == "vba" || strings.HasPrefix(name, "_vba_project") || name == "dir" || name == "project" || name == "projectwm" {
				return true
			}
		}
	}
	return false
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

// listRAR lists RAR4 file headers without invoking a decompressor. RAR5 is
// intentionally left as an opaque archive: decoding untrusted RAR data is not
// part of metadata-only analysis, and the parser must not allocate attacker
// controlled dictionaries. The caller still retains the archive metadata and
// can raise an archive signal when a name is available.
func listRAR(content []byte, maxNames int) (names []string, encrypted bool) {
	const rar4SignatureLen = 7
	if len(content) < rar4SignatureLen || !bytes.Equal(content[:rar4SignatureLen], []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}) {
		return nil, false
	}
	const (
		headSize       = 7
		headFile       = 0x74
		flagEncrypted  = 0x0004
		flagSalt       = 0x0400
		flagLarge      = 0x0100
		flagSplitAfter = 0x0002
	)
	for offset := rar4SignatureLen; offset+headSize <= len(content) && len(names) < maxNames; {
		headType := content[offset+2]
		flags := binary.LittleEndian.Uint16(content[offset+3 : offset+5])
		size := int(binary.LittleEndian.Uint16(content[offset+5 : offset+7]))
		if size < headSize || offset+size > len(content) {
			break
		}
		if flags&flagEncrypted != 0 {
			encrypted = true
		}
		if headType == headFile {
			const fixedFileFields = 25
			if size < headSize+fixedFileFields {
				break
			}
			nameLen := int(binary.LittleEndian.Uint16(content[offset+headSize+21 : offset+headSize+23]))
			nameStart := offset + headSize + fixedFileFields
			if flags&flagLarge != 0 {
				nameStart += 8
			}
			if flags&flagSalt != 0 {
				nameStart += 8
			}
			if nameLen >= 0 && nameStart <= offset+size && nameLen <= offset+size-nameStart {
				name := strings.TrimSpace(string(content[nameStart : nameStart+nameLen]))
				if name != "" {
					names = append(names, name)
				}
			}
			packSize := uint64(binary.LittleEndian.Uint32(content[offset+headSize : offset+headSize+4]))
			if flags&flagLarge != 0 {
				packSize |= uint64(binary.LittleEndian.Uint32(content[offset+headSize+25:offset+headSize+29])) << 32
			}
			next := offset + size
			if flags&flagSplitAfter == 0 {
				if packSize > uint64(len(content)-next) {
					break
				}
				next += int(packSize)
			}
			offset = next
			continue
		}
		offset += size
	}
	return names, encrypted
}

// list7z lists 7-Zip headers. Opening one entry is only a one-byte probe used
// to distinguish encrypted data from an invalid archive; the byte is discarded
// and no archive output is written anywhere.
func list7z(content []byte, maxNames int) (names []string, encrypted bool) {
	r, err := sevenzip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, false
	}
	for _, f := range r.File {
		if len(names) >= maxNames {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		names = append(names, f.Name)
		if len(names) == 1 {
			rc, openErr := f.Open()
			if openErr != nil {
				var readErr sevenzip.ReadError
				if errors.As(openErr, &readErr) && readErr.Encrypted {
					return names, true
				}
				continue
			}
			var one [1]byte
			_, readErr := rc.Read(one[:])
			_ = rc.Close()
			var archiveErr sevenzip.ReadError
			if errors.As(readErr, &archiveErr) && archiveErr.Encrypted {
				return names, true
			}
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
