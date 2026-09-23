// Package crypto wraps AES-256-GCM for encrypting stored bodies/attachments
// (Business, ТЗ §3 / §11). The key comes from an environment variable (or KMS
// later) and never lives in the database.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Cipher seals and opens byte slices.
type Cipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(ciphertext []byte) ([]byte, error)
}

// AESGCM is a Cipher over a 32-byte key.
type AESGCM struct {
	aead cipher.AEAD
}

// New builds a cipher from a 32-byte key.
func New(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESGCM{aead: aead}, nil
}

// FromEnv reads a hex- or base64-encoded 32-byte key from env; returns nil,nil when unset.
func FromEnv(name string) (*AESGCM, error) {
	if name == "" {
		return nil, nil
	}
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	key, err := decodeKey(raw)
	if err != nil {
		return nil, fmt.Errorf("crypto: %s: %w", name, err)
	}
	return New(key)
}

func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("expected 32-byte key as hex or base64")
}

// Seal returns nonce||ciphertext.
func (c *AESGCM) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, c.aead.Seal(nil, nonce, plaintext, nil)...), nil
}

// Open reverses Seal.
func (c *AESGCM) Open(data []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	return c.aead.Open(nil, data[:ns], data[ns:], nil)
}

// GenerateKey returns a fresh random key encoded as hex (for `phishlens keygen`).
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
