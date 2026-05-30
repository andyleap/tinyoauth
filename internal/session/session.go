package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Session struct {
	App               string    `json:"app"`
	Subject           string    `json:"sub"`
	Email             string    `json:"email,omitempty"`
	PreferredUsername string    `json:"preferred_username,omitempty"`
	Name              string    `json:"name,omitempty"`
	Groups            []string  `json:"groups,omitempty"`
	Expiry            time.Time `json:"exp"`
}

func (s *Session) Valid() bool { return time.Now().Before(s.Expiry) }

type FlowState struct {
	App          string    `json:"app"`
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"cv"`
	RedirectTo   string    `json:"rd"`
	Expiry       time.Time `json:"exp"`
}

func (f *FlowState) Valid() bool { return time.Now().Before(f.Expiry) }

type Codec struct {
	gcm cipher.AEAD
}

func NewCodec(key []byte) (*Codec, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Codec{gcm: g}, nil
}

func (c *Codec) Seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := c.gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func (c *Codec) Open(s string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	ns := c.gcm.NonceSize()
	if len(raw) < ns {
		return fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := c.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}
