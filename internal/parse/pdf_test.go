package parse

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPDFStaticScan(t *testing.T) {
	pdf := []byte("%PDF-1.7\n1 0 obj << /Type /Page >> endobj\n" +
		"/JavaScript /OpenAction /AA /AcroForm /EmbeddedFile\n" +
		"(Confirm payment) https://kaspi-secure.example/login\n%%EOF")
	m, err := New().PDF(pdf)
	require.NoError(t, err)
	require.NotNil(t, m.PDF)
	require.Equal(t, 1, m.PDF.Pages)
	require.True(t, m.PDF.HasJavaScript)
	require.True(t, m.PDF.HasOpenAction)
	require.True(t, m.PDF.HasForms)
	require.True(t, m.PDF.HasEmbedded)
	require.Contains(t, m.TextBody, "Confirm payment")
	require.Len(t, m.Links, 1)
	require.Equal(t, "kaspi-secure.example", m.Links[0].Domain)
}

func TestPDFRejectsNonPDF(t *testing.T) {
	_, err := New().PDF([]byte("not a PDF"))
	require.Error(t, err)
}
