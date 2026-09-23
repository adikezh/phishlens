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

// listRAR lists RAR4 and RAR5 file headers without invoking a decompressor.
// RAR5 parsing is limited to bounded metadata headers; compressed data and
// attacker-controlled dictionaries are never opened.
func listRAR(content []byte, maxNames int) (names []string, encrypted bool) {
	const rar4SignatureLen = 7
	if len(content) >= 8 && bytes.Equal(content[:8], []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}) {
		return listRAR5(content, maxNames)
	}
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

const (
	rar5SignatureLen = 8
	rar5HeaderMax    = 2 << 20
	rar5FlagExtra    = 0x0001
	rar5FlagData     = 0x0002
	rar5FileHeader   = 2
	rar5Encryption   = 4
	rar5EndHeader    = 5
	rar5FileDir      = 0x0001
	rar5FileTime     = 0x0002
	rar5FileCRC      = 0x0004
)

// listRAR5 reads only the RAR5 generic and file header fields. The format's
// header size is bounded to the specification's current 2 MiB maximum, and
// every variable integer is limited to ten bytes / uint64.
func listRAR5(content []byte, maxNames int) (names []string, encrypted bool) {
	if maxNames <= 0 || len(content) < rar5SignatureLen ||
		!bytes.Equal(content[:rar5SignatureLen], []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}) {
		return nil, false
	}
	for offset := rar5SignatureLen; offset+5 <= len(content) && len(names) < maxNames; {
		// Four bytes CRC precede the VInt header size. CRC is intentionally not
		// trusted for parsing; bounds checks below are the security boundary.
		headerStart := offset + 4
		headerSize, n, ok := readRAR5VInt(content[headerStart:])
		if !ok || headerSize > rar5HeaderMax {
			return names, encrypted
		}
		bodyStart := headerStart + n
		headerEnd := bodyStart + int(headerSize)
		if headerEnd < bodyStart || headerEnd > len(content) {
			return names, encrypted
		}
		cursor := bodyStart
		headerType, used, ok := readRAR5VInt(content[cursor:headerEnd])
		if !ok {
			return names, encrypted
		}
		cursor += used
		headerFlags, used, ok := readRAR5VInt(content[cursor:headerEnd])
		if !ok {
			return names, encrypted
		}
		cursor += used
		var extraSize, dataSize uint64
		if headerFlags&rar5FlagExtra != 0 {
			extraSize, used, ok = readRAR5VInt(content[cursor:headerEnd])
			if !ok {
				return names, encrypted
			}
			cursor += used
		}
		if headerFlags&rar5FlagData != 0 {
			dataSize, used, ok = readRAR5VInt(content[cursor:headerEnd])
			if !ok {
				return names, encrypted
			}
			cursor += used
		}
		if headerType == rar5Encryption {
			return names, true
		}
		if headerType == rar5FileHeader {
			fileFlags, next, ok := readRAR5VInt(content[cursor:headerEnd])
			if !ok {
				return names, encrypted
			}
			cursor += next
			if _, next, ok = readRAR5VInt(content[cursor:headerEnd]); !ok { // unpacked size
				return names, encrypted
			}
			cursor += next
			if _, next, ok = readRAR5VInt(content[cursor:headerEnd]); !ok { // attributes
				return names, encrypted
			}
			cursor += next
			if fileFlags&rar5FileTime != 0 {
				if cursor+4 > headerEnd {
					return names, encrypted
				}
				cursor += 4
			}
			if fileFlags&rar5FileCRC != 0 {
				if cursor+4 > headerEnd {
					return names, encrypted
				}
				cursor += 4
			}
			if _, next, ok = readRAR5VInt(content[cursor:headerEnd]); !ok { // compression
				return names, encrypted
			}
			cursor += next
			if _, next, ok = readRAR5VInt(content[cursor:headerEnd]); !ok { // host OS
				return names, encrypted
			}
			cursor += next
			nameLen, next, ok := readRAR5VInt(content[cursor:headerEnd])
			if !ok {
				return names, encrypted
			}
			cursor += next
			if nameLen > uint64(headerEnd-cursor) {
				return names, encrypted
			}
			if fileFlags&rar5FileDir == 0 && nameLen > 0 {
				names = append(names, string(content[cursor:cursor+int(nameLen)]))
			}
			cursor += int(nameLen)
		}
		if extraSize > uint64(headerEnd-cursor) {
			return names, encrypted
		}
		extraStart := headerEnd - int(extraSize)
		if extraSize > 0 {
			for p := extraStart; p < headerEnd; {
				recordSize, used, ok := readRAR5VInt(content[p:headerEnd])
				if !ok || recordSize < 1 || recordSize > uint64(headerEnd-p-used) {
					return names, encrypted
				}
				recordStart := p + used
				recordType, _, ok := readRAR5VInt(content[recordStart : recordStart+int(recordSize)])
				if !ok {
					return names, encrypted
				}
				if recordType == 1 { // file encryption record
					encrypted = true
				}
				p = recordStart + int(recordSize)
			}
		}
		if headerType == rar5EndHeader {
			return names, encrypted
		}
		if headerFlags&rar5FlagData != 0 {
			if dataSize > uint64(len(content)-headerEnd) {
				return names, encrypted
			}
			offset = headerEnd + int(dataSize)
		} else {
			offset = headerEnd
		}
	}
	return names, encrypted
}

func readRAR5VInt(data []byte) (uint64, int, bool) {
	var value uint64
	for i, b := range data {
		if i >= 10 || (i == 9 && b > 1) {
			return 0, 0, false
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, i + 1, true
		}
	}
	return 0, 0, false
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
