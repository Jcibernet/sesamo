package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// UUIDv7 generates a time-ordered UUID (RFC 9562) in Go, so we do not
// depend on Postgres 18's native uuidv7(). Layout: 48-bit Unix millis
// timestamp, 4-bit version, 12 bits rand, 2-bit variant, 62 bits rand.
//
// Time-ordered means good B-tree index locality (like a serial) while
// remaining non-enumerable (unlike a serial), which is exactly why the
// spec picked UUIDv7 for externally-visible primary keys.
func UUIDv7() string {
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		panic("crypto: rand failed: " + err.Error())
	}

	ms := uint64(time.Now().UnixMilli())
	// 48-bit timestamp in the first 6 bytes.
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(b[0:6], ts[2:8])

	// Version 7 in the high nibble of byte 6.
	b[6] = (b[6] & 0x0f) | 0x70
	// Variant 10xx in the high bits of byte 8.
	b[8] = (b[8] & 0x3f) | 0x80

	return formatUUID(b)
}

func formatUUID(b [16]byte) string {
	var dst [36]byte
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst[:])
}
