package main

import (
	"encoding/json"
	"flag"
	"strings"
)

// runState reports what a running service is doing.
//
// It asks the service rather than the kernel, because the questions an operator
// has here are about intent as much as outcome: which peers are being tried,
// how many times, and why the last attempt failed. The kernel knows only what
// succeeded.
func runState(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("state", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	asJSON := flags.Bool("json", false, "print as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh state --config <path> [--json]\n\n" +
			"Report the sessions a running service is holding or attempting.\n\n" +
			"This asks the service, so it shows what is being tried and why the\n" +
			"last attempt failed. For host state as the kernel sees it, and for\n" +
			"nodes where no service runs, use 'nostmesh status'.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh state: --config is required\n")
		return exitUsage
	}

	cfg, code := loadConfigFlag("state", []string{"--config", *configPath}, stderr, nil)
	if code != exitOK {
		return code
	}

	state, err := queryControl(controlSocketPath(cfg.Node.StateDir))
	if err != nil {
		// A service that is not running is an ordinary situation, not an error
		// in this command. Saying so plainly, and pointing at what does work,
		// beats an error that reads like a bug.
		stderr.printf("no service is running; start one with 'nostmesh serve --config %s'\n", *configPath)
		stderr.printf("for host state as the kernel sees it, run 'nostmesh status --config %s'\n", *configPath)
		return exitError
	}

	if *asJSON {
		encoded, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			stderr.printf("nostmesh state: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	stdout.printf("node %s\n", state.Node)

	if len(state.Peers) == 0 {
		stdout.printf("no peers configured\n")
		return exitOK
	}

	stdout.printf("\n%-20s %-10s %-14s %8s  %s\n", "PEER", "SHORT", "PHASE", "ATTEMPTS", "SINCE")
	for _, peer := range state.Peers {
		alias := peer.Alias
		if alias == "" {
			alias = "(no alias)"
		}
		stdout.printf("%-20s %-10s %-14s %8d  %s\n",
			truncate(alias, 20), peer.Peer, peer.Phase, peer.Attempts, peer.Since)
	}

	// The reason a peer is not connected is the point of asking, so it is
	// printed in full rather than squeezed into a column.
	for _, peer := range state.Peers {
		if peer.Reason == "" {
			continue
		}
		stdout.printf("\n%s: %s\n", peer.Peer, firstLine(peer.Reason))
	}

	return exitOK
}

// truncate shortens a field to fit its column.
func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	return value[:width-1] + "…"
}

// firstLine keeps a multi-line failure readable in a summary.
func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index] + " …"
	}
	return value
}
