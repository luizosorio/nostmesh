// Command nostmesh is the single, self-contained NostMesh binary.
//
// The CLI, the daemon and the auxiliary service roles are all subcommands of
// this executable. It links statically, requires no runtime dependencies, and
// never shells out to external tools to produce a network effect.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// command is one top-level subcommand.
type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr *output) int
}

func commands() []command {
	return []command{
		{"version", "Print build information", runVersion},
		{"config", "Inspect and validate configuration", runConfig},
		{"identity", "Manage this node's identity", runIdentity},
		{"peer", "Manage configured peers", runPeer},
		{"status", "Report configured and observed state", runStatus},
		{"up", "Bring the configured tunnel up", runUp},
		{"down", "Remove what NostMesh applied", runDown},
		{"doctor", "Check prerequisites and diagnose problems", runDoctor},
		{"serve", "Hold sessions with every authorized peer", runServe},
		{"state", "Report what a running service is doing", runState},
		{"connect", "Negotiate a session with a peer", runConnect},
		{"sessions", "List authorized peers and active sessions", runSessions},
		{"disconnect", "Close a session", runDisconnect},
		{"relay-check", "Check real relays accept this protocol", runRelayCheck},
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	out := &output{w: stdout}
	errOut := &output{w: stderr}

	if len(args) == 0 {
		usage(errOut)
		return exitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(out)
		return exitOK
	}

	for _, cmd := range commands() {
		if cmd.name == args[0] {
			return cmd.run(args[1:], out, errOut)
		}
	}

	errOut.printf("nostmesh: unknown command %q\n\n", args[0])
	usage(errOut)
	return exitUsage
}

func usage(out *output) {
	out.printf("nostmesh - decentralized overlay network\n\n")
	out.printf("Usage:\n  nostmesh <command> [flags]\n\nCommands:\n")

	for _, cmd := range commands() {
		out.printf("  %-10s %s\n", cmd.name, cmd.summary)
	}

	out.printf("\nRun 'nostmesh <command> --help' for details about a command.\n")
}

// output wraps a writer so subcommands share one formatting helper and tests
// can capture what the CLI prints.
type output struct {
	w io.Writer
}

func (o *output) printf(format string, args ...any) {
	// A failed write to stdout or stderr leaves nothing useful to do: reporting
	// it would need the same broken stream. The error is dropped deliberately.
	_, _ = fmt.Fprintf(o.w, format, args...)
}
