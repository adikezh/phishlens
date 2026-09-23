// Package attachment implements A-01 … A-06 on attachment metadata only —
// contents are never executed (ТЗ §11).
// TODO(A-02): rar/7z listing (nwaples/rardecode, bodgit/sevenzip).
// TODO(A-05): VirusTotal / MalwareBazaar hash lookup (reputation stage).
package attachment

import (
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDDangerousExt      = "attachment.dangerous_ext"      // A-01
	IDDoubleExt         = "attachment.double_ext"         // A-01
	IDRTLOverride       = "attachment.rtl_override"       // A-01
	IDArchiveEncrypted  = "attachment.archive_encrypted"  // A-02
	IDArchiveExecutable = "attachment.archive_executable" // A-02
	IDMacro             = "attachment.macro"              // A-03
	IDHTMLActive        = "attachment.html_active"        // A-06
	IDPDFActive         = "attachment.pdf_active"         // A-04
)

// Register adds attachment checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDDangerousExt, domain.CategoryAttachment, dangerousName),
		signals.NewFunc(IDArchiveEncrypted, domain.CategoryAttachment, archive),
		signals.NewFunc(IDMacro, domain.CategoryAttachment, macro),
		signals.NewFunc(IDHTMLActive, domain.CategoryAttachment, htmlActive),
		signals.NewFunc(IDPDFActive, domain.CategoryAttachment, pdfActive),
	)
}
