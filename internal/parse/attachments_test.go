package parse

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"testing"
)

func TestAttachmentFromListsNested7zEntriesWithoutExtracting(t *testing.T) {
	// Small 7z fixture containing entries named bar and foo. The parser only reads
	// headers and probes one byte; it never writes an extracted file.
	encoded := "N3q8ryccAASgR6WICAAAAAAAAABmAAAAAAAAAN2R8/FiYXIKZm9vCgEEBgACCQQEAAcLAgABAQABAQAMBAQACAoB6bOiBKhlMn4AAAUCGQUAAAAAABERAGIAYQByAAAAZgBvAG8AAAAZAgAAFBIBAACFM3PyY9YBAFgCcvJj1gEVCgEAIICkgSCApIEAAA=="
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	p := New()
	a := p.attachmentFrom("invoice.7z", "application/x-7z-compressed", content)
	if !a.IsArchive {
		t.Fatal("7z was not classified as an archive")
	}
	if len(a.NestedNames) != 2 || a.NestedNames[0] != "bar" || a.NestedNames[1] != "foo" {
		t.Fatalf("nested names = %#v, want [bar foo]", a.NestedNames)
	}
	if a.PasswordProtected {
		t.Fatal("plain 7z fixture was marked password protected")
	}
}

func TestAttachmentFromListsNestedZipEntriesAndHonorsLimit(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"readme.txt", "run.exe"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	p := New()
	p.Limits.MaxArchiveNames = 1
	a := p.attachmentFrom("bundle.zip", "application/zip", buf.Bytes())
	if len(a.NestedNames) != 1 || a.NestedNames[0] != "readme.txt" {
		t.Fatalf("nested names = %#v, want one bounded entry", a.NestedNames)
	}
}

func TestListRARRejectsInvalidInputWithoutPanic(t *testing.T) {
	names, encrypted := listRAR([]byte("not a rar"), 10)
	if names != nil || encrypted {
		t.Fatalf("invalid RAR result = %#v, %v", names, encrypted)
	}
}

func TestListRAR5ReadsHeadersWithoutDecompression(t *testing.T) {
	content := append([]byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, rar5TestHeader(2, 0x2, 3, []byte{
		0, // file flags
		0, // unpacked size
		0, // attributes
		0, // compression
		0, // host OS
		3, 'r', 'u', 'n',
	})...)
	content = append(content, rar5TestHeader(5, 0, 0, []byte{0})...)
	names, encrypted := listRAR(content, 10)
	if len(names) != 1 || names[0] != "run" || encrypted {
		t.Fatalf("RAR5 result = %#v, %v; want [run], false", names, encrypted)
	}
}

func TestListRAR5MarksEncryptionHeader(t *testing.T) {
	content := append([]byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, rar5TestHeader(4, 0, 0, []byte{0})...)
	_, encrypted := listRAR(content, 10)
	if !encrypted {
		t.Fatal("RAR5 encryption header was not reported")
	}
}

func rar5TestHeader(headerType, flags uint64, dataSize uint64, fields []byte) []byte {
	body := append(rar5VInt(headerType), rar5VInt(flags)...)
	if flags&0x2 != 0 {
		body = append(body, rar5VInt(dataSize)...)
	}
	body = append(body, fields...)
	out := []byte{0, 0, 0, 0}
	out = append(out, rar5VInt(uint64(len(body)))...)
	out = append(out, body...)
	if flags&0x2 != 0 {
		out = append(out, bytes.Repeat([]byte{0xCC}, int(dataSize))...)
	}
	return out
}

func rar5VInt(value uint64) []byte {
	var out []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if value == 0 {
			return out
		}
	}
}

func TestOLEMacroProbeRejectsNonCompoundInput(t *testing.T) {
	if oleHasVBA([]byte("not an OLE document")) {
		t.Fatal("non-OLE input was marked as containing VBA")
	}
}
