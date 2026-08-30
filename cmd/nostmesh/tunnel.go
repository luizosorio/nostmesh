package main

import (
	"context"
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

func journalDir(stateDir string) string {
	return filepath.Join(stateDir, "journal")
}

// buildOrchestrator wires the real Linux adapter to the orchestrator.
//
// It returns a cleanup function, because the netlink control socket must be
// released even when the command fails.
func buildOrchestrator(cfg config.Config) (*orchestrator.Orchestrator, func(), error) {
	adapter, closeAdapter, err := wireguard.NewController()
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = closeAdapter() }

	generator := identity.NewKeyGenerator()

	instance, err := orchestrator.New(orchestrator.Options{
		Controller:  adapter,
		Journal:     netstate.NewJournalStore(journalDir(cfg.Node.StateDir)),
		Clock:       domain.SystemClock{},
		GenerateKey: generator.Generate,
	})
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return instance, cleanup, nil
}

// loadConfigFlag parses the shared --config flag.
func loadConfigFlag(name string, args []string, stderr *output, extra func(*flag.FlagSet)) (config.Config, int) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	if extra != nil {
		extra(flags)
	}

	if err := flags.Parse(args); err != nil {
		return config.Config{}, exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh %s: --config is required\n", name)
		return config.Config{}, exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return config.Config{}, exitError
	}
	return cfg, exitOK
}

func runStatus(args []string, stdout, stderr *output) int {
	cfg, code := loadConfigFlag("status", args, stderr, nil)
	if code != exitOK {
		return code
	}

	instance, cleanup, err := buildOrchestrator(cfg)
	if err != nil {
		stderr.printf("nostmesh status: %v\n", err)
		return exitError
	}
	defer cleanup()

	status, err := instance.Status(context.Background(), cfg)
	if err != nil {
		stderr.printf("nostmesh status: %v\n", err)
		return exitError
	}

	return renderStatus(status, cfg, stdout)
}

// renderStatus prints desired configuration beside observed host state.
//
// Showing both is the point: the gap between them is what tells an operator
// whether the tunnel is merely configured or actually working.
func renderStatus(status orchestrator.Status, cfg config.Config, stdout *output) int {
	stdout.printf("node:      %s\n", cfg.Node.Name)
	stdout.printf("interface: %s\n", status.Interface)

	if status.ObserveFailed != nil {
		stdout.printf("state:     unknown (%v)\n", status.ObserveFailed)
	} else if status.InterfaceUp {
		stdout.printf("state:     up\n")
	} else {
		stdout.printf("state:     down\n")
	}

	stdout.printf("\nconfigured peers: %d\n", len(status.Configured))
	for _, peer := range status.Configured {
		stdout.printf("  %s\n", peer.Name)
		stdout.printf("    endpoint:    %s\n", peer.Endpoint)
		stdout.printf("    allowed ips: %s\n", strings.Join(peer.AllowedIPs, ", "))
		renderObservedPeer(status, peer, stdout)
	}

	if status.Observed != nil {
		stdout.printf("\nobserved: MTU %d, listen port %d\n",
			status.Observed.MTU, status.Observed.ListenPort)
	}

	return renderPending(status, stdout)
}

// renderObservedPeer reports what the kernel says about one configured peer.
func renderObservedPeer(status orchestrator.Status, peer config.Peer, stdout *output) {
	if status.Observed == nil {
		stdout.printf("    observed:    not configured on the host\n")
		return
	}

	key, err := domain.ParseWireGuardPublicKey(peer.PublicKey)
	if err != nil {
		stdout.printf("    observed:    unreadable public key\n")
		return
	}

	for _, observed := range status.Observed.Peers {
		if observed.PublicKey != key {
			continue
		}
		if observed.HasHandshake() {
			stdout.printf("    observed:    handshake %s ago, rx %d, tx %d\n",
				time.Since(observed.LastHandshake).Round(time.Second),
				observed.ReceiveBytes, observed.TransmitBytes)
		} else {
			stdout.printf("    observed:    present, no handshake yet\n")
		}
		return
	}

	stdout.printf("    observed:    not configured on the host\n")
}

func renderPending(status orchestrator.Status, stdout *output) int {
	if len(status.Pending) == 0 {
		stdout.printf("\njournal: no interrupted transactions\n")
		return exitOK
	}

	stdout.printf("\njournal: %d interrupted transaction(s)\n", len(status.Pending))
	for _, transaction := range status.Pending {
		stdout.printf("  %s on %s, started %s\n",
			transaction.ID, transaction.Interface, transaction.StartedAt.Format(time.RFC3339))
	}
	stdout.printf("\nthe host may carry partial state; run 'nostmesh down' to reconcile\n")

	return exitOK
}

func runUp(args []string, stdout, stderr *output) int {
	var dryRun *bool
	cfg, code := loadConfigFlag("up", args, stderr, func(flags *flag.FlagSet) {
		dryRun = flags.Bool("dry-run", false, "describe the changes without applying them")
	})
	if code != exitOK {
		return code
	}

	// A dry run describes changes without touching the host, so it must work
	// without the netlink socket — an operator checking what would happen
	// should not need privileges to do it.
	controller := wireguard.Controller(nil)
	var cleanup = func() {}

	if dryRun == nil || !*dryRun {
		adapter, closeAdapter, adapterErr := wireguard.NewController()
		if adapterErr != nil {
			stderr.printf("nostmesh up: %v\n", adapterErr)
			return exitError
		}
		controller = adapter
		cleanup = func() { _ = closeAdapter() }
	} else {
		controller = wireguard.NewFakeController()
	}
	defer cleanup()

	instance, err := orchestrator.New(orchestrator.Options{
		Controller:  controller,
		Journal:     netstate.NewJournalStore(journalDir(cfg.Node.StateDir)),
		Clock:       domain.SystemClock{},
		GenerateKey: identity.NewKeyGenerator().Generate,
	})
	if err != nil {
		stderr.printf("nostmesh up: %v\n", err)
		return exitError
	}

	ctx := context.Background()

	plan, err := instance.PlanUp(ctx, cfg)
	if err != nil {
		if errors.Is(err, orchestrator.ErrNoPeers) {
			stderr.printf("nostmesh up: no peers configured; add one with 'nostmesh peer add'\n")
			return exitError
		}
		stderr.printf("nostmesh up: %v\n", err)
		return exitError
	}

	if dryRun != nil && *dryRun {
		stdout.printf("dry run: no changes will be applied\n\n")
		for _, line := range plan.Describe() {
			stdout.printf("  %s\n", line)
		}
		stdout.printf("\n%d operation(s) would be applied\n", len(plan.Operations))
		return exitOK
	}

	transaction, err := instance.Up(ctx, cfg)
	if err != nil {
		stderr.printf("nostmesh up: %v\n", err)
		stderr.printf("the host was left as it was found\n")
		return exitError
	}

	stdout.printf("tunnel up on %s\n", transaction.Interface)
	stdout.printf("  %d operation(s) applied\n", len(transaction.AppliedOperations()))
	stdout.printf("  %d peer(s) configured\n", len(cfg.Peers))

	return exitOK
}

func runDown(args []string, stdout, stderr *output) int {
	cfg, code := loadConfigFlag("down", args, stderr, nil)
	if code != exitOK {
		return code
	}

	instance, cleanup, err := buildOrchestrator(cfg)
	if err != nil {
		stderr.printf("nostmesh down: %v\n", err)
		return exitError
	}
	defer cleanup()

	result, err := instance.Down(context.Background())
	if err != nil {
		stderr.printf("nostmesh down: %v\n", err)
		return exitError
	}

	if len(result.Removed) == 0 && len(result.Interrupted) == 0 {
		stdout.printf("nothing to remove\n")
		return exitOK
	}

	for _, removed := range result.Removed {
		stdout.printf("removed %s\n", removed)
	}
	for _, kept := range result.Kept {
		stdout.printf("kept %s (not owned by nostmesh)\n", kept)
	}
	if len(result.Interrupted) > 0 {
		stdout.printf("reconciled %d interrupted transaction(s)\n", len(result.Interrupted))
	}

	return exitOK
}
