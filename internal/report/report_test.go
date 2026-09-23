package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/store"
)

func sampleStats() *store.Stats {
	return &store.Stats{
		Total: 3, ByVerdict: map[string]int{"phishing": 1, "clean": 2},
		ByStatus: map[string]int{"analyzed": 3}, ByAttackType: map[string]int{"credential_harvesting": 1},
		TopBrands: []store.NameCount{{Name: "Kaspi", Count: 1}}, AvgDuration: 42,
	}
}

func TestDOCXReportIsReadableZip(t *testing.T) {
	b, err := docx(sampleStats())
	require.NoError(t, err)
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	require.NoError(t, err)
	var document string
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		r, err := f.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(r)
		r.Close()
		require.NoError(t, err)
		document = string(data)
	}
	require.Contains(t, document, "Total submissions: 3")
}

func TestPDFReportHasCrossReference(t *testing.T) {
	b := pdf(sampleStats())
	require.True(t, bytes.HasPrefix(b, []byte("%PDF-1.4")))
	require.Contains(t, string(b), "xref")
	require.Contains(t, string(b), "startxref")
	require.Contains(t, string(b), "Total submissions: 3")
}

func TestPDFASCIIEscapesSyntax(t *testing.T) {
	require.Equal(t, `a\(b\)\\c`, pdfASCII(`a(b)\c`))
	require.True(t, strings.Contains(string(pdf(sampleStats())), "%%EOF"))
}
