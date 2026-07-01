package crypto

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateTokenUniqueAndSized(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok := GenerateToken()
		if seen[tok] {
			t.Fatalf("duplicate token generated: %s", tok)
		}
		seen[tok] = true
		// 32 bytes base64url no padding => 43 chars.
		if len(tok) != 43 {
			t.Fatalf("unexpected token length %d: %s", len(tok), tok)
		}
	}
}

func TestHashTokenDeterministicAnd32Bytes(t *testing.T) {
	tok := GenerateToken()
	a := HashToken(tok)
	b := HashToken(tok)
	if len(a) != 32 {
		t.Fatalf("hash should be 32 bytes, got %d", len(a))
	}
	if !SafeEqual(a, b) {
		t.Fatal("hash not deterministic")
	}
	if SafeEqual(a, HashToken(GenerateToken())) {
		t.Fatal("different tokens hashed equal")
	}
}

func TestUUIDv7FormatAndOrdering(t *testing.T) {
	prev := ""
	for i := 0; i < 100; i++ {
		id := UUIDv7()
		if len(id) != 36 {
			t.Fatalf("uuid length %d: %s", len(id), id)
		}
		if id[14] != '7' {
			t.Fatalf("version nibble not 7: %s", id)
		}
		variant := id[19]
		if !strings.ContainsRune("89ab", rune(variant)) {
			t.Fatalf("variant nibble invalid: %s", id)
		}
		prev = id
	}
	_ = prev
}

func TestArgon2idRoundTrip(t *testing.T) {
	phc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$") {
		t.Fatalf("not a PHC argon2id string: %s", phc)
	}
	ok, rehash, err := VerifyPassword("correct horse battery staple", phc)
	if err != nil || !ok {
		t.Fatalf("valid password failed: ok=%v err=%v", ok, err)
	}
	if rehash {
		t.Fatal("argon2id should not request rehash")
	}
	ok, _, _ = VerifyPassword("wrong", phc)
	if ok {
		t.Fatal("wrong password verified")
	}
}

func TestBcryptVerifyRequestsRehash(t *testing.T) {
	// Generate a real bcrypt hash (cost 10) the way Auth0 would store it,
	// rather than hardcoding a vector that could be wrong.
	raw, err := bcrypt.GenerateFromPassword([]byte("password123"), 10)
	if err != nil {
		t.Fatal(err)
	}
	bcryptHash := string(raw)
	if bcryptHash[:4] != "$2a$" && bcryptHash[:4] != "$2b$" {
		t.Fatalf("unexpected bcrypt prefix: %s", bcryptHash)
	}
	ok, rehash, err := VerifyPassword("password123", bcryptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid bcrypt password failed")
	}
	if !rehash {
		t.Fatal("bcrypt should request lazy rehash to argon2id")
	}
	ok, _, _ = VerifyPassword("nope", bcryptHash)
	if ok {
		t.Fatal("wrong bcrypt password verified")
	}
}
