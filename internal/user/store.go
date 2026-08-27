package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// Store provides user/identity data access.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore constructs a user Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// OAuthProfile is the normalized profile returned by a provider.
type OAuthProfile struct {
	Provider      string
	Sub           string
	Email         string
	EmailVerified bool
	Name          *string
	PictureURL    *string
}

// UpsertResult reports the resolved user id and whether it was created.
type UpsertResult struct {
	UserID string
	IsNew  bool
}

// ErrSignupDisabled is returned by UpsertByOAuth when resolving the
// profile would require creating a brand-new user and the deployment's
// signup policy forbids it. Identities that resolve to an existing user
// (linked or matched by email) are unaffected.
var ErrSignupDisabled = errors.New("signup disabled: new user creation is not allowed")

// ErrUserDisabled is returned by UpsertByOAuth when the profile resolves
// to an account whose kill switch is on. The provider already vouched
// for the identity, so this is an authorization outcome, not an
// authentication one: callers must answer with their generic login
// failure and start no session.
var ErrUserDisabled = errors.New("user disabled: login is not allowed")

// UpsertByOAuth resolves a user from an OAuth profile. It links by
// (provider, provider_sub) first; if no identity exists it links to an
// existing user by email, or — only when allowCreate — creates a new
// user. Returns whether the user account was newly created.
func (s *Store) UpsertByOAuth(ctx context.Context, p OAuthProfile, allowCreate bool) (UpsertResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UpsertResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Existing identity? Resolve the owner and its kill switch in one
	// round trip: a disabled account must not even get its profile
	// fields refreshed.
	var (
		userID   string
		disabled bool
	)
	err = tx.QueryRow(ctx, `
		SELECT i.user_id, u.disabled
		FROM identities i
		JOIN users u ON u.id = i.user_id
		WHERE i.provider = $1 AND i.provider_sub = $2`,
		p.Provider, p.Sub).Scan(&userID, &disabled)
	if err == nil {
		if disabled {
			return UpsertResult{}, ErrUserDisabled
		}
		// Refresh mutable profile fields.
		if _, err := tx.Exec(ctx,
			`UPDATE users SET name = $2, picture_url = $3, updated_at = now() WHERE id = $1`,
			userID, p.Name, p.PictureURL); err != nil {
			return UpsertResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return UpsertResult{}, err
		}
		return UpsertResult{UserID: userID, IsNew: false}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return UpsertResult{}, err
	}

	// 2. Existing user by email? Link a new identity to it — unless it is
	// disabled, in which case linking would hand the account back.
	isNew := false
	err = tx.QueryRow(ctx, `SELECT id, disabled FROM users WHERE email = $1`, p.Email).
		Scan(&userID, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		// 3. Create a new user.
		if !allowCreate {
			return UpsertResult{}, ErrSignupDisabled
		}
		userID = crypto.UUIDv7()
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, email, email_verified, name, picture_url)
			 VALUES ($1, $2, $3, $4, $5)`,
			userID, p.Email, p.EmailVerified, p.Name, p.PictureURL); err != nil {
			return UpsertResult{}, err
		}
		isNew = true
	} else if err != nil {
		return UpsertResult{}, err
	} else if disabled {
		return UpsertResult{}, ErrUserDisabled
	}

	// Link the identity.
	if _, err := tx.Exec(ctx,
		`INSERT INTO identities (id, user_id, provider, provider_sub)
		 VALUES ($1, $2, $3, $4)`,
		crypto.UUIDv7(), userID, p.Provider, p.Sub); err != nil {
		return UpsertResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return UpsertResult{}, err
	}
	return UpsertResult{UserID: userID, IsNew: isNew}, nil
}

// ByID loads a user by id.
func (s *Store) ByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, email_verified, disabled, name, picture_url, created_at, metadata
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Disabled,
			&u.Name, &u.PictureURL, &u.CreatedAt, &u.Metadata)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ByEmail loads a user by email. Returns (nil, nil) when not found.
func (s *Store) ByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, email_verified, disabled, name, picture_url, created_at, metadata
		 FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Disabled,
			&u.Name, &u.PictureURL, &u.CreatedAt, &u.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
