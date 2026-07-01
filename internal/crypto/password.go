package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters. Tuned for interactive logins: ~64MB memory, 1
// pass with 4 lanes is the RFC 9106 "second recommended" profile and is
// a sane default for a single-binary server.
const (
	argonMemory  = 64 * 1024 // KiB => 64 MiB
	argonTime    = 1
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrMismatch is returned when a password does not match the hash.
var ErrMismatch = errors.New("crypto: password mismatch")

// HashPassword hashes a plaintext password with Argon2id and returns a
// PHC-format string ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		b64(salt), b64(hash)), nil
}

// VerifyPassword checks a plaintext password against a stored PHC hash.
// It supports both Argon2id ($argon2id$...) hashes that we produce and
// bcrypt ($2a$/$2b$/$2y$...) hashes imported from Auth0.
//
// The second return value reports whether the hash is a legacy format
// (bcrypt) that should be re-hashed to Argon2id on the next successful
// login.
func VerifyPassword(password, phc string) (ok bool, needsRehash bool, err error) {
	switch {
	case strings.HasPrefix(phc, "$argon2id$"):
		ok, err = verifyArgon2id(password, phc)
		return ok, false, err
	case strings.HasPrefix(phc, "$2a$"),
		strings.HasPrefix(phc, "$2b$"),
		strings.HasPrefix(phc, "$2y$"):
		err = bcrypt.CompareHashAndPassword([]byte(phc), []byte(password))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, false, nil
			}
			return false, false, err
		}
		// Valid bcrypt hash => flag for lazy migration to Argon2id.
		return true, true, nil
	default:
		return false, false, fmt.Errorf("crypto: unknown hash format")
	}
}

func verifyArgon2id(password, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 {
		return false, fmt.Errorf("crypto: malformed argon2id hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("crypto: argon2 version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("crypto: unsupported argon2 version %d", version)
	}

	var mem uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false, fmt.Errorf("crypto: argon2 params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("crypto: argon2 salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("crypto: argon2 hash: %w", err)
	}

	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// DummyVerify performs an Argon2id computation against a fixed hash to
// equalize timing when a user does not exist (anti-enumeration). The
// result is intentionally discarded by the caller.
func DummyVerify(password string) {
	// A precomputed valid Argon2id hash of a random string. The compare
	// will always fail, but the cost mirrors a real verification.
	_, _, _ = VerifyPassword(password, dummyArgonHash)
}

// dummyArgonHash is a static Argon2id hash used only for timing.
const dummyArgonHash = "$argon2id$v=19$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$" +
	"R6dQ4F1mQ8m0d3o0r0kE2v0c0Xq7yQ1mYrJ8t8a0aA"
