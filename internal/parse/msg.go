package parse

import (
	"bytes"
	"fmt"

	"github.com/phishlens/phishlens/internal/domain"
)

// cfbMagic is the OLE2 compound-file signature.
var cfbMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// MSG parses an Outlook .msg (CFB/OLE2 → MAPI properties).
//
// TODO(F-4.1.3): richardlehane/mscfb + MAPI property parser:
//   - __substg1.0_0037001F (subject), 0C1F (sender email), 1000 (body), 1013 (html)
//   - __recip_version1.0_#… (recipients), __attach_version1.0_#… (attachments)
//   - transport headers 007D001F → reuse ParseReceived/ParseAuthResults.
func (p *Parser) MSG(data []byte) (*domain.ParsedMail, error) {
	if len(data) < 8 || !bytes.Equal(data[:8], cfbMagic) {
		return nil, fmt.Errorf("parse msg: not an OLE2 compound file")
	}
	return nil, fmt.Errorf("%w: .msg (CFB/MAPI) parser", ErrNotImplemented)
}
