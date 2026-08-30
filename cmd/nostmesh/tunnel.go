package main

import (
	"flag"
	"path/filepath"
	"strings"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/netstate"
)

func journalDir(stateDir string) string {
	return filepath.Join(stateDir, "journal")
}

// runStatus reports desired configuration against observed host state.
//
// Showing both is the point: a session the configuration expects but the kernel
// does not have is exactly the situation an operator needs to see.
func runStatus(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh status --config <path>\n\n" +
			"Report the configured peers and what the host currently carries.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh status: --config is required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	stdout.printf("node:  %s\n", cfg.Node.Name)
	stdout.printf("state: %s\n\n", cfg.Node.StateDir)

	stdout.printf("configured peers: %d\n", len(cfg.Peers))
	for _, peer := range cfg.Peers {
		stdout.printf("  %s\n", peer.Name)
		stdout.printf("    endpoint: %s\n", peer.Endpoint)
		stdout.printf("    overlay:  %s\n", peer.OverlayAddress)
		stdout.printf("    allowed:  %s\n", strings.Join(peer.AllowedIPs, ", "))
	}

	return reportJournal(cfg, stdout, stderr)
}

// reportJournal surfaces interrupted transactions, which is what tells an
// operator the host may be carrying partial state.
func reportJournal(cfg config.Config, stdout, stderr *output) int {
	journal := netstate.NewJournalStore(journalDir(cfg.Node.StateDir))

	pending, err := journal.PendingRecovery()
	if err != nil {
		stderr.printf("nostmesh status: reading journal: %v\n", err)
		return exitError
	}

	if len(pending) == 0 {
		stdout.printf("\njournal: no interrupted transactions\n")
		return exitOK
	}

	stdout.printf("\njournal: %d interrupted transaction(s)\n", len(pending))
	for _, transaction := range pending {
		stdout.printf("  %s on %s, started %s\n",
			transaction.ID, transaction.Interface, transaction.StartedAt.Format(time.RFC3339))
		for _, op := range transaction.Operations {
			if op.Status == netstate.StatusApplying || op.Status == netstate.StatusApplied {
				stdout.printf("    %s %s: %s\n", op.Status, op.Kind, op.Detail)
			}
		}
	}
	stdout.printf("\nthe host may carry partial state; run 'nostmesh down' to reconcile\n")

	return exitOK
}

// runUp is the placeholder for bringing a tunnel up.
//
// The transactional machinery it needs exists, but wiring it to a live
// interface requires the orchestrator that M0.4 introduces. Failing with a
// clear message beats a command that half works.
func runUp(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("up", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	dryRun := flags.Bool("dry-run", false, "describe the changes without applying them")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh up --config <path> [--dry-run]\n\n" +
			"Bring the configured tunnel up.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh up: --config is required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	if *dryRun {
		return describePlan(cfg, stdout)
	}

	stderr.printf("nostmesh up: not implemented yet; the orchestrator arrives in M0.4\n")
	stderr.printf("use --dry-run to see the changes that would be applied\n")
	return exitError
}

// describePlan renders what would change, without touching the host.
func describePlan(cfg config.Config, stdout *output) int {
	stdout.printf("dry run: no changes will be applied\n\n")
	stdout.printf("interface nm0\n")
	stdout.printf("  addresses: derived from peer overlay configuration\n")
	stdout.printf("  MTU:       1420\n\n")

	if len(cfg.Peers) == 0 {
		stdout.printf("no peers configured\n")
		return exitOK
	}

	stdout.printf("peers:\n")
	for _, peer := range cfg.Peers {
		stdout.printf("  %s\n", peer.Name)
		stdout.printf("    endpoint:    %s\n", peer.Endpoint)
		stdout.printf("    allowed ips: %s\n", strings.Join(peer.AllowedIPs, ", "))
	}

	stdout.printf("\n%d operation(s) would be applied\n", len(cfg.Peers)+4)
	return exitOK
}

// runDown reconciles the host against the journal, removing what NostMesh
// applied and leaving everything else alone.
func runDown(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("down", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh down --config <path>\n\n" +
			"Remove what NostMesh applied and reconcile the journal.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh down: --config is required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	journal := netstate.NewJournalStore(journalDir(cfg.Node.StateDir))
	pending, err := journal.PendingRecovery()
	if err != nil {
		stderr.printf("nostmesh down: reading journal: %v\n", err)
		return exitError
	}

	if len(pending) == 0 {
		stdout.printf("nothing to reconcile\n")
		return exitOK
	}

	stdout.printf("%d interrupted transaction(s) recorded:\n", len(pending))
	for _, transaction := range pending {
		stdout.printf("  %s on %s\n", transaction.ID, transaction.Interface)
	}

	stderr.printf("\nnostmesh down: reconciliation is not implemented yet; the orchestrator arrives in M0.4\n")
	return exitError
}
