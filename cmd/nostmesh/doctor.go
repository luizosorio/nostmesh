package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// checkResult is one diagnostic outcome.
type checkResult struct {
	Name   string
	Status string
	Detail string
}

const (
	statusOK    = "ok"
	statusWarn  = "warn"
	statusError = "error"
)

// runDoctor verifies the prerequisites a working tunnel depends on.
//
// It never changes anything: its job is to turn "it does not work" into a
// specific missing prerequisite. Output is deliberately free of key material,
// so it can be pasted into an issue.
func runDoctor(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh doctor --config <path>\n\n" +
			"Check the prerequisites for a working tunnel. Changes nothing.\n" +
			"Output carries no key material and is safe to share.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh doctor: --config is required\n")
		return exitUsage
	}

	checks := []checkResult{checkConfiguration(*configPath)}

	cfg, err := config.Load(*configPath)
	if err == nil {
		checks = append(checks,
			checkStateDir(cfg),
			checkIdentity(cfg),
			checkJournal(cfg),
			checkPeers(cfg),
		)
		checks = append(checks, checkWireGuard(cfg)...)
	}

	return renderChecks(checks, stdout)
}

func renderChecks(checks []checkResult, stdout *output) int {
	failed := 0
	for _, check := range checks {
		marker := map[string]string{statusOK: "✓", statusWarn: "!", statusError: "✗"}[check.Status]
		stdout.printf("%s %-22s %s\n", marker, check.Name, check.Detail)
		if check.Status == statusError {
			failed++
		}
	}

	stdout.printf("\n%d check(s), %d problem(s)\n", len(checks), failed)
	if failed > 0 {
		return exitError
	}
	return exitOK
}

func checkConfiguration(path string) checkResult {
	if _, err := config.Load(path); err != nil {
		return checkResult{"configuration", statusError, err.Error()}
	}
	return checkResult{"configuration", statusOK, path}
}

func checkStateDir(cfg config.Config) checkResult {
	info, err := os.Stat(cfg.Node.StateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checkResult{"state directory", statusWarn,
				fmt.Sprintf("%s does not exist yet; it is created on first use", cfg.Node.StateDir)}
		}
		return checkResult{"state directory", statusError, err.Error()}
	}
	if !info.IsDir() {
		return checkResult{"state directory", statusError,
			fmt.Sprintf("%s is not a directory", cfg.Node.StateDir)}
	}
	return checkResult{"state directory", statusOK, cfg.Node.StateDir}
}

func checkIdentity(cfg config.Config) checkResult {
	keystore := identity.NewDevelopmentKeystore(defaultKeystorePath(cfg.Node.StateDir), nil)

	exists, err := keystore.Exists()
	if err != nil {
		return checkResult{"identity", statusError, err.Error()}
	}
	if !exists {
		return checkResult{"identity", statusWarn,
			fmt.Sprintf("none yet; run 'nostmesh identity init --state-dir %s'", cfg.Node.StateDir)}
	}

	node, err := keystore.Load()
	if err != nil {
		return checkResult{"identity", statusError, err.Error()}
	}
	return checkResult{"identity", statusOK, node.PublicKey().Short()}
}

func checkJournal(cfg config.Config) checkResult {
	journal := netstate.NewJournalStore(journalDir(cfg.Node.StateDir))

	pending, err := journal.PendingRecovery()
	if err != nil {
		return checkResult{"journal", statusError, err.Error()}
	}
	if len(pending) > 0 {
		return checkResult{"journal", statusWarn,
			fmt.Sprintf("%d interrupted transaction(s); run 'nostmesh down' to reconcile", len(pending))}
	}
	return checkResult{"journal", statusOK, "no interrupted transactions"}
}

func checkPeers(cfg config.Config) checkResult {
	if len(cfg.Peers) == 0 {
		return checkResult{"peers", statusWarn, "none configured; add one with 'nostmesh peer add'"}
	}
	return checkResult{"peers", statusOK, fmt.Sprintf("%d configured", len(cfg.Peers))}
}

// checkWireGuard verifies the kernel side: the control socket, and whether the
// interface is present and carrying handshakes.
func checkWireGuard(cfg config.Config) []checkResult {
	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		return []checkResult{{"wireguard", statusError,
			fmt.Sprintf("cannot open the control socket: %v; is the wireguard module loaded and does this process have CAP_NET_ADMIN?", err)}}
	}
	defer func() { _ = adapter.Close() }()

	checks := []checkResult{{"wireguard", statusOK, "control socket available"}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	observed, err := adapter.ObserveInterface(ctx, "nm0")
	switch {
	case errors.Is(err, wireguard.ErrInterfaceNotFound):
		return append(checks, checkResult{"interface nm0", statusWarn,
			"not present; run 'nostmesh up' to bring the tunnel up"})
	case err != nil:
		return append(checks, checkResult{"interface nm0", statusError, err.Error()})
	}

	checks = append(checks, checkResult{"interface nm0", statusOK,
		fmt.Sprintf("up, MTU %d, %d peer(s)", observed.MTU, len(observed.Peers))})

	withHandshake := 0
	for _, peer := range observed.Peers {
		if peer.HasHandshake() {
			withHandshake++
		}
	}

	switch {
	case len(observed.Peers) == 0:
		checks = append(checks, checkResult{"handshakes", statusWarn, "no peers on the interface"})
	case withHandshake == 0:
		checks = append(checks, checkResult{"handshakes", statusWarn,
			"no peer has completed a handshake; check endpoint reachability and UDP connectivity"})
	default:
		checks = append(checks, checkResult{"handshakes", statusOK,
			fmt.Sprintf("%d of %d peer(s)", withHandshake, len(observed.Peers))})
	}

	return checks
}
