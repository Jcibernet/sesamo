package email

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// testKey returns a deterministic 32-byte key encoded for a keyring spec.
func testKey(seed byte) string {
	key := bytes.Repeat([]byte{seed}, keySize)
	return base64.StdEncoding.EncodeToString(key)
}

func TestKeyringRoundTrip(t *testing.T) {
	kr, err := ParseKeyring("k1:" + testKey(1))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	plaintext := []byte("https://auth.example/reset/confirm?token=secret")
	aad := payloadAAD("00000000-0000-7000-8000-000000000001", "resend", "reset")

	keyID, nonce, ciphertext, err := kr.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if keyID != "k1" {
		t.Fatalf("key id = %q, want k1", keyID)
	}
	if len(nonce) != nonceSize {
		t.Fatalf("nonce len = %d, want %d", len(nonce), nonceSize)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains the plaintext link")
	}

	got, err := kr.Decrypt(keyID, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestKeyringNonceIsFreshPerEncryption(t *testing.T) {
	kr, err := ParseKeyring("k1:" + testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	aad := payloadAAD("id", "resend", "reset")
	_, n1, c1, err := kr.Encrypt([]byte("same body"), aad)
	if err != nil {
		t.Fatal(err)
	}
	_, n2, c2, err := kr.Encrypt([]byte("same body"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce reused across encryptions (GCM key/nonce reuse is catastrophic)")
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("identical ciphertexts leak that two payloads are equal")
	}
}

// A payload is bound to its row: moving a ciphertext onto another outbox
// id (or replaying it under another purpose) must not open.
func TestKeyringAADMismatchFails(t *testing.T) {
	kr, err := ParseKeyring("k1:" + testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	aad := payloadAAD("row-a", "resend", "reset")
	keyID, nonce, ciphertext, err := kr.Encrypt([]byte("link"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string][]byte{
		"other row":     payloadAAD("row-b", "resend", "reset"),
		"other purpose": payloadAAD("row-a", "resend", "magiclink"),
		"no aad":        nil,
	} {
		if _, err := kr.Decrypt(keyID, nonce, ciphertext, other); !errors.Is(err, ErrPayloadAuth) {
			t.Fatalf("%s: err = %v, want ErrPayloadAuth", name, err)
		}
	}
}

func TestKeyringTamperedCiphertextFails(t *testing.T) {
	kr, err := ParseKeyring("k1:" + testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	aad := payloadAAD("row", "resend", "verify")
	keyID, nonce, ciphertext, err := kr.Encrypt([]byte("link"), aad)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0xff
	if _, err := kr.Decrypt(keyID, nonce, ciphertext, aad); !errors.Is(err, ErrPayloadAuth) {
		t.Fatalf("err = %v, want ErrPayloadAuth", err)
	}
}

// Overlapped rotation: the new key encrypts, the retired key still opens
// jobs queued before the deploy.
func TestKeyringRotationDecryptsOldEncryptsActive(t *testing.T) {
	old, err := ParseKeyring("old:" + testKey(5))
	if err != nil {
		t.Fatal(err)
	}
	aad := payloadAAD("row", "resend", "reset")
	oldKeyID, nonce, ciphertext, err := old.Encrypt([]byte("queued before rotation"), aad)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := ParseKeyring("new:" + testKey(6) + ",old:" + testKey(5))
	if err != nil {
		t.Fatalf("ParseKeyring rotated: %v", err)
	}
	if rotated.ActiveKeyID() != "new" {
		t.Fatalf("active key = %q, want new (first entry encrypts)", rotated.ActiveKeyID())
	}
	got, err := rotated.Decrypt(oldKeyID, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("decrypt with retired key: %v", err)
	}
	if string(got) != "queued before rotation" {
		t.Fatalf("payload = %q", got)
	}
	freshID, _, _, err := rotated.Encrypt([]byte("queued after rotation"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if freshID != "new" {
		t.Fatalf("new payload used key %q, want new", freshID)
	}

	// The retired-only keyring cannot open what the active key sealed:
	// that is what makes dropping a key a real revocation.
	if _, err := old.Decrypt(freshID, nonce, ciphertext, aad); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("err = %v, want ErrUnknownKeyID", err)
	}
}

func TestParseKeyringErrors(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	cases := []struct {
		name string
		spec string
		want error
	}{
		{"empty", "", ErrEmptyKeyring},
		{"blank", "   ", ErrEmptyKeyring},
		{"no separator", "justakey", ErrKeyringEntry},
		{"missing id", ":" + testKey(8), ErrKeyringEntry},
		{"missing key", "k1:", ErrKeyringEntry},
		{"empty entry", "k1:" + testKey(8) + ",", ErrKeyringEntry},
		{"not base64", "k1:@@@@not-base64@@@@", ErrKeyringEntry},
		{"wrong size", "k1:" + short, ErrKeySize},
		{"duplicate id", "k1:" + testKey(8) + ",k1:" + testKey(9), ErrDuplicateKeyID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr, err := ParseKeyring(tc.spec)
			if kr != nil {
				t.Fatal("a malformed spec must not produce a usable keyring")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// A keyring error can end up in a boot log: it must never
			// carry key material.
			if strings.Contains(err.Error(), testKey(8)) || strings.Contains(err.Error(), short) {
				t.Fatalf("error leaks key material: %v", err)
			}
		})
	}
}

func TestParseKeyringAcceptsBase64Variants(t *testing.T) {
	raw := bytes.Repeat([]byte{0xfb}, keySize) // encodes with '+' and '/' in std
	for name, encoded := range map[string]string{
		"std":     base64.StdEncoding.EncodeToString(raw),
		"rawstd":  base64.RawStdEncoding.EncodeToString(raw),
		"url":     base64.URLEncoding.EncodeToString(raw),
		"rawurl":  base64.RawURLEncoding.EncodeToString(raw),
		"padding": " k1:" + base64.StdEncoding.EncodeToString(raw) + " ",
	} {
		spec := "k1:" + encoded
		if strings.HasPrefix(name, "padding") {
			spec = encoded
		}
		if _, err := ParseKeyring(spec); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestEphemeralKeyring(t *testing.T) {
	kr, err := NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if kr.ActiveKeyID() != "ephemeral" {
		t.Fatalf("active key = %q", kr.ActiveKeyID())
	}
	aad := payloadAAD("row", "log", "magiclink")
	keyID, nonce, ciphertext, err := kr.Encrypt([]byte("dev link"), aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kr.Decrypt(keyID, nonce, ciphertext, aad)
	if err != nil || string(got) != "dev link" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	// A second boot key cannot read the first one's payloads: pending dev
	// jobs fail closed across a restart instead of silently changing key.
	other, err := NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Decrypt(keyID, nonce, ciphertext, aad); !errors.Is(err, ErrPayloadAuth) {
		t.Fatalf("err = %v, want ErrPayloadAuth", err)
	}
}
