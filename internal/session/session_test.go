package session

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestCodecRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	in := Session{
		App:     "demo",
		Subject: "user-123",
		Email:   "u@example.com",
		Groups:  []string{"admins", "devs"},
		Expiry:  time.Now().Add(time.Hour).Round(time.Second),
	}
	enc, err := c.Seal(&in)
	if err != nil {
		t.Fatal(err)
	}
	var out Session
	if err := c.Open(enc, &out); err != nil {
		t.Fatal(err)
	}
	if out.Subject != in.Subject || out.App != in.App || out.Email != in.Email {
		t.Fatalf("mismatch: %+v vs %+v", in, out)
	}
	if len(out.Groups) != 2 || out.Groups[0] != "admins" {
		t.Fatalf("groups mismatch: %+v", out.Groups)
	}
	if !out.Valid() {
		t.Fatal("expected valid")
	}
}

func TestCodecTampering(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	c, _ := NewCodec(key)
	enc, _ := c.Seal(&Session{Subject: "x", Expiry: time.Now().Add(time.Hour)})
	// flip a byte in the middle of the ciphertext
	b := []byte(enc)
	b[len(b)/2] ^= 1
	var out Session
	if err := c.Open(string(b), &out); err == nil {
		t.Fatal("expected open to fail on tampered ciphertext")
	}
}

func TestCodecKeyMismatch(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	c1, _ := NewCodec(k1)
	c2, _ := NewCodec(k2)
	enc, _ := c1.Seal(&Session{Subject: "x", Expiry: time.Now().Add(time.Hour)})
	var out Session
	if err := c2.Open(enc, &out); err == nil {
		t.Fatal("expected open to fail with wrong key")
	}
}
