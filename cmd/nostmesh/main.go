// Command nostmesh is the single, self-contained NostMesh binary.
//
// The CLI, the daemon and the auxiliary service roles are all subcommands of
// this executable. It links statically, requires no runtime dependencies, and
// never shells out to external tools to produce a network effect.
package main

import (
	"fmt"
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
	}
}

func run(args []string, stdout, stderr writer) int {
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

// writer is the minimal sink the CLI writes to, so tests can capture output
// without touching the filesystem.
type writer interface {
	Write(p []byte) (int, error)
}

type output struct {
	w writer
}

func (o *output) printf(format string, args ...any) {
	fmt.Fprintf(o.w, format, args...)
}
