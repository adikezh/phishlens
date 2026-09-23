package parse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"  // register decoders for DecodeConfig
	_ "image/jpeg" // register decoders for DecodeConfig
	"image/png"
	"net/url"
	"strings"

	"github.com/corona10/goimagehash"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/phishlens/phishlens/internal/domain"
)

// Image handles screenshot input (F-4.1.9): decodes header with pixel limits,
// hashes it, then runs OCR when a backend is configured. Without OCR it returns
// the partially filled mail and ErrOCRUnavailable so the caller can degrade.
func (p *Parser) Image(ctx context.Context, data []byte) (*domain.ParsedMail, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse image: %w", err)
	}
	if cfg.Width*cfg.Height > p.Limits.MaxImagePixels {
		return nil, fmt.Errorf("%w: %dx%d pixels", ErrTooLarge, cfg.Width, cfg.Height)
	}
	sum := sha256.Sum256(data)
	mime := "image/" + format
	pm := &domain.ParsedMail{
		Headers: map[string][]string{},
		Images: []domain.InlineImage{{
			MIME: mime, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
			Width: cfg.Width, Height: cfg.Height,
		}},
	}
	decoded, _, decodeErr := image.Decode(bytes.NewReader(data))
	if decodeErr == nil {
		if hash, hashErr := goimagehash.PerceptionHash(decoded); hashErr == nil {
			pm.Images[0].PHash = hash.ToString()
		}
		if qrURL := decodeQR(decoded); qrURL != "" {
			pm.Links = append(pm.Links, domain.Link{Href: qrURL, Text: "QR"})
		}
	}
	if p.OCR == nil {
		p.finish(pm)
		return pm, ErrOCRUnavailable
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("parse image: decode pixels: %w", decodeErr)
	}
	// Re-encode decoded pixels before an external OCR/vision call. This drops
	// EXIF/GPS and other metadata while retaining visible content.
	ocrData, ocrMIME := sanitizedImage(decoded, data, mime)
	text, urls, err := p.OCR.Extract(ctx, ocrData, ocrMIME)
	if err != nil {
		return pm, fmt.Errorf("parse image: ocr: %w", err)
	}
	pm.OCRText = text
	pm.TextBody = text
	for _, u := range urls {
		pm.Links = append(pm.Links, domain.Link{Href: u, Text: "ocr"})
	}
	p.finish(pm)
	return pm, nil
}

func decodeQR(img image.Image) string {
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return ""
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(result.GetText())
	u, err := url.Parse(text)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return text
}

func imageFrom(content []byte, mime string, maxPixels int) domain.InlineImage {
	sum := sha256.Sum256(content)
	img := domain.InlineImage{MIME: mime, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(content)); err == nil && cfg.Width*cfg.Height <= maxPixels {
		img.Width, img.Height = cfg.Width, cfg.Height
	}
	if decoded, _, err := image.Decode(bytes.NewReader(content)); err == nil {
		if hash, hashErr := goimagehash.PerceptionHash(decoded); hashErr == nil {
			img.PHash = hash.ToString()
		}
	}
	return img
}

func sanitizedImage(decoded image.Image, original []byte, mime string) ([]byte, string) {
	if decoded == nil {
		return original, mime
	}
	var out bytes.Buffer
	if err := png.Encode(&out, decoded); err != nil {
		return original, mime
	}
	return out.Bytes(), "image/png"
}
