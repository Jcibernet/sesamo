// Command sesamo is the single static binary: an auth server with
// opaque Postgres-backed sessions, OAuth, email flows, an embedded
// themeable login UI, and an S2S introspection API.
//
// Subcommands:
//
//	sesamo migrate   run idempotent migrations and exit
//	sesamo serve     run migrations then start the HTTP server
//	sesamo admin ... administrative commands (e.g. import)
//	sesamo describe  print the deployment descriptor as JSON and exit
//	sesamo version   print the build version and exit
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/db"
)

// version is the build version, stamped at link time with
//
//	-ldflags "-X main.version=v1.2.3"
//
// Unstamped builds (go run, go build without flags) report "dev".
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sesamo <migrate|serve|admin|describe|version>")
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "migrate":
		os.Exit(runMigrate(log))
	case "serve":
		os.Exit(runServe(log))
	case "admin":
		os.Exit(runAdmin(log, os.Args[2:]))
	case "describe":
		os.Exit(runDescribe(log, os.Args[2:]))
	case "version":
		fmt.Println(version)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func runMigrate(log *slog.Logger) int {
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
	if err := db.Migrate(ctx, pool, log); err != nil {
		log.Error("migrate", "err", err)
		return 1
	}
	log.Info("migrations up to date")
	return 0
}

func runServe(log *slog.Logger) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		return 1
	}
	// The build version is a link-time value, not an env var: main is the
	// only place that knows it, and the descriptor publishes it.
	cfg.Version = version
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db connect", "err", err)
		return 1
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool, log); err != nil {
		log.Error("migrate", "err", err)
		return 1
	}

	if err := serve(ctx, cfg, pool, log); err != nil {
		log.Error("serve", "err", err)
		return 1
	}
	return 0
}
