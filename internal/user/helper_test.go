package user

import "github.com/jcibernet/sesamo/internal/crypto"

// randSuffix returns a short random string for unique test fixtures.
func randSuffix() string {
	return crypto.GenerateToken()[:12]
}
