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
// Strategy: stream the NDJSON file line by line, inserting accounts
// with their EXISTING bcrypt hash stored verbatim. Passwords keep
// working immediately and are transparently re-hashed to Argon2id on
// the user's first successful login (lazy migration) — no password
// reset emails, no big-bang cutover. Re-running the import is
// idempotent: existing emails are skipped, and a skip does NOT update
// other fields (name, email_verified) that may have changed upstream.
//
// Rows are flushed in pipelined batches of importChunkSize so a bulk
// import over a high-RTT link costs ~1 round trip per chunk instead of
// per user. A failed chunk (one implicit transaction, nothing kept) is
// replayed row-by-row to isolate and report the offending record.

// importChunkSize bounds rows per pipelined batch: large enough to
// amortize RTT, small enough to keep a replay-on-error cheap.
const importChunkSize = 500

// pendingRow pairs a parsed record with its source line for reporting.
type pendingRow struct {
	rec  user.ImportRecord
	line int
}

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

	pending := make([]pendingRow, 0, importChunkSize)
	// flush imports the pending chunk in one batch; on batch error it
	// replays the chunk row-by-row so one bad record fails alone.
	flush := func() {
		if len(pending) == 0 {
			return
		}
		recs := make([]user.ImportRecord, len(pending))
		for i, p := range pending {
			recs[i] = p.rec
		}
		n, err := store.ImportBatch(ctx, recs)
		if err == nil {
			created += n
			skipped += len(recs) - n
			pending = pending[:0]
			return
		}
		log.Warn("batch failed, replaying rows individually", "rows", len(pending), "err", err)
		for _, p := range pending {
			outcome, err := store.Import(ctx, p.rec)
			if err != nil {
				log.Error("import row failed", "line", p.line, "email", p.rec.Email, "err", err)
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
		pending = pending[:0]
	}

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

		pending = append(pending, pendingRow{
			rec: user.ImportRecord{
				Email:         rec.Email,
				EmailVerified: rec.EmailVerified,
				PasswordHash:  rec.hash(),
				Name:          rec.Name,
			},
			line: line,
		})
		if len(pending) >= importChunkSize {
			flush()
		}
	}
	if err := sc.Err(); err != nil {
		log.Error("read export", "err", err)
		return 1
	}
	flush()

	log.Info("import complete",
		"created", created, "skipped", skipped, "failed", failed, "total_lines", line)
	if failed > 0 {
		return 1
	}
	return 0
}
