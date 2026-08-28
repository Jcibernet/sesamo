package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jcibernet/sesamo/internal/config"
	httpapi "github.com/jcibernet/sesamo/internal/http"
)

// runDescribe implements `sesamo describe`: it prints the same
// descriptor GET /.well-known/sesamo serves, built by the same function,
// without connecting to Postgres. That matters for the audience — an
// agent or an operator inspecting a deployment's contract from a
// container that may not have (or want) database credentials.
//
// JSON is the only output, so --json is accepted and ignored rather than
// required: an agent that passes the flag it read in the usage line and
// one that passes nothing get identical bytes.
func runDescribe(log *slog.Logger, args []string) int {
	for _, a := range args {
		if a != "--json" {
			fmt.Fprintf(os.Stderr, "usage: sesamo describe [--json]\n")
			return 2
		}
	}

	cfg, err := config.LoadForDescribe()
	if err != nil {
		log.Error("config", "err", err)
		return 1
	}
	cfg.Version = version

	doc, err := httpapi.DescribeJSON(cfg)
	if err != nil {
		log.Error("describe", "err", err)
		return 1
	}
	fmt.Println(string(doc))
	return 0
}
