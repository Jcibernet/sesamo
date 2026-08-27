package email

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Keyring encrypts and decrypts queued email payloads at rest.
//
// The queued body carries a bearer link, so storing it in clear would
// undo Sésamo's standing property that Postgres holds only token
// hashes. AES-256-GCM gives confidentiality plus authentication, and the
// associated data binds a ciphertext to the exact outbox row it belongs
// to: a row copied over another one fails to open.
//
// Rotation is overlapped: the first key of the spec encrypts, every key
// decrypts. Operators add the new key in front, deploy, and only then
// drop the old one — no window where a queued job becomes unreadable.
//
// Key material never appears in an error message, a log line, or the
// String of anything here.
type Keyring struct {
	activeID string
	aeads    map[string]cipher.AEAD
}

// Keyring errors. They name the failure without echoing key material,
// the spec, or the payload.
var (
	ErrEmptyKeyring   = errors.New("email: empty outbox keyring spec")
	ErrKeyringEntry   = errors.New("email: outbox keyring entry must be <id>:<base64-32-bytes>")
	ErrKeySize        = errors.New("email: outbox key must decode to exactly 32 bytes")
	ErrDuplicateKeyID = errors.New("email: duplicate outbox key id")
	ErrUnknownKeyID   = errors.New("email: unknown outbox key id")
	ErrPayloadAuth    = errors.New("email: outbox payload failed authentication")
)

// nonceSize is the GCM standard nonce length. Nonces are random per
// encryption: the payload count per key is minuscule (one per auth
// email), so 96 random bits are far from the birthday bound.
const nonceSize = 12

// keySize is AES-256.
const keySize = 32

// ParseKeyring builds a Keyring from
// "<active-id>:<base64-32-bytes>[,<older-id>:<key>...]". Key ids are
// opaque labels stored next to the ciphertext; they are not secret.
// A malformed spec is a boot failure, never a silent downgrade to
// plaintext.
func ParseKeyring(spec string) (*Keyring, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, ErrEmptyKeyring
	}
	kr := &Keyring{aeads: make(map[string]cipher.AEAD)}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, ErrKeyringEntry
		}
		id, encoded, ok := strings.Cut(entry, ":")
		id, encoded = strings.TrimSpace(id), strings.TrimSpace(encoded)
		if !ok || id == "" || encoded == "" {
			return nil, ErrKeyringEntry
		}
		key, err := decodeKey(encoded)
		if err != nil {
			// %w on the sentinel only: the offending value is the key.
			return nil, fmt.Errorf("email: outbox key %q: %w", id, err)
		}
		if _, dup := kr.aeads[id]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKeyID, id)
		}
		aead, err := newAEAD(key)
		if err != nil {
			return nil, fmt.Errorf("email: outbox key %q: %w", id, err)
		}
		kr.aeads[id] = aead
		if kr.activeID == "" {
			kr.activeID = id // first entry encrypts
		}
	}
	return kr, nil
}

// NewEphemeralKeyring generates a random key held only in memory, under
// the id "ephemeral". It exists so local development does not have to
// configure a keyring to exercise the outbox — production config
// requires SESAMO_EMAIL_OUTBOX_KEYS. Jobs still pending across a restart
// become undecryptable and fail closed, which is the correct trade for a
// dev default: no plaintext link ever reaches Postgres.
func NewEphemeralKeyring() (*Keyring, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("email: generate ephemeral outbox key: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Keyring{activeID: "ephemeral", aeads: map[string]cipher.AEAD{"ephemeral": aead}}, nil
}

// ActiveKeyID reports which key new payloads are encrypted with. Useful
// for operator diagnostics during a rotation; it is not secret.
func (k *Keyring) ActiveKeyID() string { return k.activeID }

// Encrypt seals plaintext under the active key. aad is authenticated but
// not stored: callers must be able to reconstruct it exactly (the outbox
// uses id|provider|purpose from the row).
func (k *Keyring) Encrypt(plaintext, aad []byte) (keyID string, nonce, ciphertext []byte, err error) {
	aead, ok := k.aeads[k.activeID]
	if !ok {
		return "", nil, nil, ErrUnknownKeyID
	}
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, nil, fmt.Errorf("email: outbox nonce: %w", err)
	}
	return k.activeID, nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// Decrypt opens a payload with the key it was sealed under. A wrong key
// id, a tampered ciphertext, and a mismatched aad are all reported as
// authentication failures — the caller cannot tell them apart, and does
// not need to: every one of them means this payload is unusable.
func (k *Keyring) Decrypt(keyID string, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, ok := k.aeads[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
	}
	if len(nonce) != nonceSize {
		return nil, ErrPayloadAuth
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrPayloadAuth
	}
	return plaintext, nil
}

// decodeKey accepts standard or URL-safe base64, padded or not: an
// operator pasting from a key manager should not have to guess which
// alphabet Sésamo wants.
func decodeKey(encoded string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(encoded); err == nil {
			if len(key) != keySize {
				return nil, ErrKeySize
			}
			return key, nil
		}
	}
	return nil, ErrKeyringEntry
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
