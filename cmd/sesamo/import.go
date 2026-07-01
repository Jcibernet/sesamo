package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/db"
	"github.com/jcibernet/sesamo/internal/user"
)

// auth0Record models the fields we consume from an Auth0 bulk user
// export (NDJSON, one JSON object per line). Auth0's export extension
// emits bcrypt hashes in "passwordHash"; we also accept "password_hash".
type auth0Record struct {
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	PasswordHash  string  `json:"passwordHash"`
	PasswordHash2 string  `json:"password_hash"`
	Name          *string `json:"name"`
}

func (r auth0Record) hash() string {
	if r.PasswordHash != "" {
		return r.PasswordHash
	}
	return r.PasswordHash2
}

// runImport implements `sesamo admin import <auth0-export.ndjson>`.
//
// Strategy: stream the NDJSON file line by line, inserting each account
// with its EXISTING bcrypt hash stored verbatim. Passwords keep working
// immediately and are transparently re-hashed to Argon2id on the user's
// first successful login (lazy migration) — no password reset emails, no
// big-bang cutover. Re-running the import is idempotent (existing emails
// are skipped).
func runImport(log *slog.Logger, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sesamo admin import <auth0-export.ndjson>")
		return 2
	}
	path := args[0]

	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		return 1
	}
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db connect", "err", err)
		return 1
	}
	defer pool.Close()

	f, err := os.Open(path)
	if err != nil {
		log.Error("open export", "err", err, "path", path)
		return 1
	}
	defer f.Close()

	store := user.NewStore(pool)
	var created, skipped, failed, line int

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024) // allow long lines
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var rec auth0Record
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			log.Warn("skip malformed line", "line", line, "err", err)
			failed++
			continue
		}
		if rec.Email == "" {
			log.Warn("skip line without email", "line", line)
			failed++
			continue
		}

		outcome, err := store.Import(ctx, user.ImportRecord{
			Email:         rec.Email,
			EmailVerified: rec.EmailVerified,
			PasswordHash:  rec.hash(),
			Name:          rec.Name,
		})
		if err != nil {
			log.Error("import row failed", "line", line, "email", rec.Email, "err", err)
			failed++
			continue
		}
		switch outcome {
		case user.ImportCreated:
			created++
		case user.ImportSkipped:
			skipped++
		}
	}
	if err := sc.Err(); err != nil {
		log.Error("read export", "err", err)
		return 1
	}

	log.Info("import complete",
		"created", created, "skipped", skipped, "failed", failed, "total_lines", line)
	if failed > 0 {
		return 1
	}
	return 0
}
