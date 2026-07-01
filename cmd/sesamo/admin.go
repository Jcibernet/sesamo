package main

import (
	"fmt"
	"log/slog"
	"os"
)

// runAdmin dispatches `sesamo admin <subcommand>`. The import command is
// implemented in Step 8.
func runAdmin(log *slog.Logger, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sesamo admin <import> [args]")
		return 2
	}
	switch args[0] {
	case "import":
		return runImport(log, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand %q\n", args[0])
		return 2
	}
}
