// Package crypto holds server-only cryptographic helpers: opaque token
// generation, session-token hashing (SHA-256), password hashing
// (Argon2id) and verification, bcrypt verification for Auth0-imported
// hashes, and constant-time comparison.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// TokenBytes is the entropy size of opaque tokens: 256 bits.
const TokenBytes = 32

// GenerateToken returns a cryptographically random opaque token encoded
// as base64url without padding (~43 chars). Used for session tokens and
// one-time tokens. 256 bits makes brute force infeasible even with DB
// access, and it is URL/cookie safe without escaping.
func GenerateToken() string {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto: rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateOAuthState returns a 128-bit random value for OAuth state and
// PKCE-related cookies.
func GenerateOAuthState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto: rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns SHA-256(token) as a 32-byte slice. This is what we
// store in Postgres (BYTEA). SHA-256 (not bcrypt/argon2) because the
// token already has 256 bits of entropy — slow hashing protects weak
// passwords, not high-entropy tokens — and this runs on every request.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// SafeEqual reports whether two byte slices are equal in constant time.
func SafeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
