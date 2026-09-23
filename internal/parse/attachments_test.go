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
