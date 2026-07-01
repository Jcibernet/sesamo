// Package user holds the user/identity domain types and data access.
package user

import "time"

// User is the canonical account record.
type User struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Name          *string        `json:"name"`
	PictureURL    *string        `json:"picture_url"`
	CreatedAt     time.Time      `json:"created_at"`
	Metadata      map[string]any `json:"metadata"`
}

// Identity links a user to an external OAuth provider subject.
type Identity struct {
	ID          string
	UserID      string
	Provider    string
	ProviderSub string
	CreatedAt   time.Time
}
