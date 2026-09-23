// Package attachment implements A-01 … A-06 on attachment metadata only —
// contents are never executed (ТЗ §11).
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
	IDVirusTotal        = "attachment.virustotal"         // A-05
)

// Register adds attachment checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDDangerousExt, domain.CategoryAttachment, dangerousExtOnly),
		signals.NewFunc(IDDoubleExt, domain.CategoryAttachment, doubleExtOnly),
		signals.NewFunc(IDRTLOverride, domain.CategoryAttachment, rtlOnly),
		signals.NewFunc(IDArchiveEncrypted, domain.CategoryAttachment, archiveEncryptedOnly),
		signals.NewFunc(IDArchiveExecutable, domain.CategoryAttachment, archiveExecutableOnly),
		signals.NewFunc(IDMacro, domain.CategoryAttachment, macro),
		signals.NewFunc(IDHTMLActive, domain.CategoryAttachment, htmlActive),
		signals.NewFunc(IDPDFActive, domain.CategoryAttachment, pdfActive),
		signals.NewFunc(IDVirusTotal, domain.CategoryAttachment, virusTotal),
	)
}
