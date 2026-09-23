// Package parse converts every input kind (eml, msg, text, image) into a
// domain.ParsedMail. Parsers are defensive: size limits, nesting limits, no
// execution of attachments, best-effort charset handling (ТЗ §11).
package parse

import (
	"context"
	"errors"
	"fmt"

	"github.com/phishlens/phishlens/internal/domain"
)

var (
	// ErrNotImplemented marks a parser that is stubbed in the skeleton.
	ErrNotImplemented = errors.New("parse: not implemented")
	// ErrOCRUnavailable is returned by Image when no OCR backend is configured;
	// the pipeline continues in degraded mode.
	ErrOCRUnavailable = errors.New("parse: OCR backend not configured")
	// ErrTooLarge is returned when an input exceeds configured limits.
	ErrTooLarge = errors.New("parse: input too large")
	// ErrEmpty is returned for empty input.
	ErrEmpty = errors.New("parse: empty input")
)

// Limits bound resource usage while parsing.
type Limits struct {
	MaxBodyBytes    int64 // per text/html part
	MaxAttachment   int64 // per attachment kept in memory for hashing/listing
	MaxParts        int   // MIME parts total
	MaxDepth        int   // multipart nesting
	MaxLinks        int
	MaxArchiveNames int
	MaxImagePixels  int
}

// DefaultLimits are conservative defaults for a 25 MB upload cap.
var DefaultLimits = Limits{
	MaxBodyBytes:    4 << 20,
	MaxAttachment:   25 << 20,
	MaxParts:        200,
	MaxDepth:        10,
	MaxLinks:        500,
	MaxArchiveNames: 200,
	MaxImagePixels:  40_000_000,
}

// OCR extracts text and visible URLs from an image (tesseract container or vision-LLM).
type OCR interface {
	Extract(ctx context.Context, image []byte, mime string) (text string, urls []string, err error)
}

// Parser holds shared options.
type Parser struct {
	Limits     Limits
	Shorteners map[string]struct{} // for Link.IsShortener
	OCR        OCR                 // nil → images return ErrOCRUnavailable
}

// New returns a Parser with default limits.
func New() *Parser {
	return &Parser{Limits: DefaultLimits}
}

// Parse dispatches on kind.
func (p *Parser) Parse(ctx context.Context, kind domain.Kind, data []byte) (*domain.ParsedMail, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	switch kind {
	case domain.KindEML:
		return p.EML(data)
	case domain.KindText:
		return p.Text(string(data))
	case domain.KindMSG:
		return p.MSG(data)
	case domain.KindImage:
		return p.Image(ctx, data)
	default:
		return nil, fmt.Errorf("parse: unknown kind %q", kind)
	}
}
