package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/policy"
)

// runConnect opens a session with a peer over the control plane.
func runConnect(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")
	timeout := flags.Duration("timeout", sessionTimeout, "how long to wait for the session to establish")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh connect --config <path> --peer <pubkey>\n\n" +
			"Negotiate a session with a peer over Nostr.\n\n" +
			"The peer must already be authorized: local policy denies by default,\n" +
			"and a valid signature proves who is asking, not that they may.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *peerKey == "" {
		stderr.printf("nostmesh connect: --config and --peer are required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	peer, err := domain.ParseNostrPublicKey(*peerKey)
	if err != nil {
		stderr.printf("nostmesh connect: %v\n", err)
		return exitError
	}

	// Policy is consulted before anything is attempted. Refusing here costs
	// nothing; refusing after a handshake wastes both sides' work.
	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		stderr.printf("nostmesh connect: %v\n", err)
		return exitError
	}
	if err := allowlist.Check(peer, policy.ActionSession); err != nil {
		stderr.printf("nostmesh connect: %v\n", err)
		stderr.printf("add it to policy.authorized_peers in %s to authorize it\n", *configPath)
		return exitError
	}

	// The pair settles which end opens the session: both are willing to do
	// either, and the command name is not evidence about the peer.
	return runSession(cfg, peer, orchestrator.RoleAuto, *timeout, stdout, stderr)
}

// runListen waits for a peer to open a session with this node.
//
// The responder has to be listening before the request arrives, which is why
// this is a foreground process rather than something `connect` could do on its
// own. It is deliberately not a daemon: a daemon needs a control socket, a pid
// file and an IPC surface, none of which the current acceptance criteria ask
// for. Supervision belongs to systemd or a container runtime.
//
// By default it keeps listening after a session ends, because the peer that
// will connect may not be ready for hours. That is also what makes the
// behaviour correct rather than merely convenient: a listener that was already
// running when a request was published sees it arrive, in order, and never has
// to guess which of several stored requests is the live one.
func runListen(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("listen", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")
	timeout := flags.Duration("timeout", 0,
		"give up after this long; zero keeps listening indefinitely")
	once := flags.Bool("once", false, "exit after the first session ends, successfully or not")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh listen --config <path> --peer <pubkey>\n\n" +
			"Wait for a peer to open a session, and answer it.\n\n" +
			"The peer must already be authorized: local policy denies by default.\n\n" +
			"This runs in the foreground and keeps listening, so the peer may\n" +
			"connect at any time — minutes or days later. It exits on SIGINT or\n" +
			"SIGTERM; run it under systemd or a container runtime to keep it up.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *peerKey == "" {
		stderr.printf("nostmesh listen: --config and --peer are required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	peer, err := domain.ParseNostrPublicKey(*peerKey)
	if err != nil {
		stderr.printf("nostmesh listen: %v\n", err)
		return exitError
	}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		stderr.printf("nostmesh listen: %v\n", err)
		return exitError
	}
	if err := allowlist.Check(peer, policy.ActionSession); err != nil {
		stderr.printf("nostmesh listen: %v\n", err)
		stderr.printf("add it to policy.authorized_peers in %s to authorize it\n", *configPath)
		return exitError
	}

	if *once {
		return runSession(cfg, peer, orchestrator.RoleAuto, *timeout, stdout, stderr)
	}
	return runListener(cfg, peer, *timeout, stdout, stderr)
}

// runListener answers sessions until it is asked to stop.
//
// Each session gets its own runtime, so a failed attempt leaves nothing behind
// for the next one: the relay set, the UDP port and the netlink socket are all
// released before another is opened. That costs a reconnection per attempt and
// buys the guarantee that one session cannot inherit another's state.
func runListener(cfg config.Config, peer domain.NostrPublicKey,
	timeout time.Duration, stdout, stderr *output,
) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		<-stop
		cancel()
	}()

	// Answered sessions are remembered across attempts, not within one. Each
	// attempt gets a fresh runtime, so a record owned by the driver would be
	// forgotten between them and the responder would answer the same dead
	// session from the relay's backlog every time — refusing every live request
	// behind it.
	answered := orchestrator.NewAnsweredSessions(time.Now)

	stdout.printf("listening for %s; press Ctrl-C to stop\n", peer.Short())

	var consecutive int
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			stdout.printf("stopped\n")
			return exitOK
		}

		err := answerOnce(ctx, cfg, peer, timeout, stdout, answered)
		switch {
		case ctx.Err() != nil:
			stdout.printf("stopped\n")
			return exitOK
		case err == nil:
			stdout.printf("tunnel established with %s\n", peer.Short())
			stdout.printf("still listening; the peer may reconnect\n")
		default:
			// A failed attempt is ordinary here: the peer may have gone away
			// mid-handshake, or not be ready yet. It is reported and the
			// listener carries on, because giving up would defeat the point of
			// waiting.
			stderr.printf("attempt %d did not complete: %v\n", attempt, err)
			consecutive++
		}

		if err == nil {
			consecutive = 0
		}

		// Backing off matters because some failures do not resolve on their
		// own. A port already held by another process fails identically every
		// time, and retrying it twice a second is a spin loop that fills the
		// log and hammers the relays without ever making progress.
		select {
		case <-ctx.Done():
			stdout.printf("stopped\n")
			return exitOK
		case <-time.After(retryDelay(consecutive)):
		}
	}
}

// answerOnce builds a runtime, answers one session, and releases everything.
func answerOnce(ctx context.Context, cfg config.Config, peer domain.NostrPublicKey,
	timeout time.Duration, stdout *output, answered *orchestrator.AnsweredSessions,
) error {
	sessionCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		sessionCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	trace := func(line string) { stdout.printf("  %s\n", line) }

	runtime, err := buildSessionRuntime(sessionCtx, cfg, peer, timeout, trace, answered)
	if err != nil {
		return err
	}
	defer runtime.cleanup()

	go runtime.set.Supervise(sessionCtx)
	go runtime.set.Poll(sessionCtx)

	return runtime.driver.Connect(sessionCtx, peer, orchestrator.RoleAuto)
}

// retryDelay spaces out attempts, growing while they keep failing.
//
// A peer that is simply not ready yet costs one short pause; a condition that
// cannot resolve — a port held by another process, a configuration the operator
// must fix — backs off to a rate that keeps the failure visible in the log
// without drowning it.
func retryDelay(consecutive int) time.Duration {
	if consecutive <= 0 {
		return listenRetryInterval
	}

	delay := listenRetryInterval << min(consecutive-1, maxRetryDoublings)
	return min(delay, maxListenRetryInterval)
}

const (
	// listenRetryInterval separates one attempt from the next.
	listenRetryInterval = 2 * time.Second

	// maxListenRetryInterval caps the backoff, so a listener still notices a
	// peer that becomes ready after a long outage.
	maxListenRetryInterval = 30 * time.Second

	// maxRetryDoublings bounds the shift, so the delay cannot overflow.
	maxRetryDoublings = 8
)

// runSession builds the runtime and drives one session to a carrying tunnel.
//
// Interrupting it tears down cleanly rather than leaving a half-configured
// interface: a signal is a request to stop, not permission to abandon kernel
// state.
func runSession(cfg config.Config, peer domain.NostrPublicKey, role orchestrator.Role,
	timeout time.Duration, stdout, stderr *output,
) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if timeout > 0 {
		var timed context.CancelFunc
		ctx, timed = context.WithTimeout(ctx, timeout)
		defer timed()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	stdout.printf("connecting to %s\n", peer.Short())

	// Progress is printed as it happens. A session spans two hosts and several
	// layers, and every failure in it looks the same from outside — a wait that
	// ends empty — so saying what did arrive is most of the diagnosis.
	trace := func(line string) { stdout.printf("  %s\n", line) }

	runtime, err := buildSessionRuntime(ctx, cfg, peer, timeout, trace, nil)
	if err != nil {
		stderr.printf("nostmesh: %v\n", err)
		return exitError
	}
	defer runtime.cleanup()

	// Relays are kept connected for the duration. A relay that drops mid-session
	// is redialled and resubscribed, since a peer may still be publishing to it.
	go runtime.set.Supervise(ctx)

	// Some relays answer a subscription from storage and then never push what
	// arrives afterwards. Polling reissues the subscription so those still
	// deliver, at the cost of a small query every few seconds.
	go runtime.set.Poll(ctx)

	if err := runtime.driver.Connect(ctx, peer, role); err != nil {
		stderr.printf("nostmesh: %v\n", err)

		// What this node managed to publish is half the diagnosis. A session
		// that failed having published nothing is a different problem from one
		// that published and was not answered.
		for _, line := range runtime.plane.Publications() {
			stderr.printf("  published %s\n", line)
		}
		return exitError
	}

	stdout.printf("tunnel established with %s\n", peer.Short())
	stdout.printf("run 'nostmesh status --config <path>' to inspect it\n")
	return exitOK
}

// runSessions lists what the node knows about its sessions.
func runSessions(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("sessions", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	asJSON := flags.Bool("json", false, "print as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh sessions --config <path> [--json]\n\n" +
			"List authorized peers and any active sessions.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh sessions: --config is required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		stderr.printf("nostmesh sessions: %v\n", err)
		return exitError
	}

	grants := allowlist.Grants()

	if *asJSON {
		rendered := make([]map[string]any, 0, len(grants))
		for _, grant := range grants {
			actions := make([]string, 0, len(grant.Actions))
			for _, action := range grant.Actions {
				actions = append(actions, string(action))
			}
			rendered = append(rendered, map[string]any{
				"peer":    grant.Peer.String(),
				"alias":   grant.Alias,
				"actions": actions,
				"revoked": grant.Revoked,
			})
		}

		encoded, err := json.Marshal(rendered)
		if err != nil {
			stderr.printf("nostmesh sessions: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	if len(grants) == 0 {
		stdout.printf("no authorized peers\n")
		stdout.printf("\nlocal policy denies by default; authorize a peer with 'nostmesh peer authorize'\n")
		return exitOK
	}

	stdout.printf("authorized peers: %d\n\n", len(grants))
	for _, grant := range grants {
		status := "active"
		if grant.Revoked {
			status = "revoked"
		}

		label := grant.Alias
		if label == "" {
			label = grant.Peer.Short()
		}

		stdout.printf("%s\n", label)
		stdout.printf("  pubkey:  %s\n", grant.Peer.String())
		stdout.printf("  actions: %s\n", joinActions(grant.Actions))
		stdout.printf("  status:  %s\n", status)
	}

	stdout.printf("\nno active sessions; the relay transport arrives in M1.4\n")
	return exitOK
}

// runDisconnect closes a session.
func runDisconnect(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("disconnect", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh disconnect --config <path> --peer <pubkey>\n\n" +
			"Close a session and remove what it applied to the host.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *peerKey == "" {
		stderr.printf("nostmesh disconnect: --config and --peer are required\n")
		return exitUsage
	}

	if _, err := config.Load(*configPath); err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}
	if _, err := domain.ParseNostrPublicKey(*peerKey); err != nil {
		stderr.printf("nostmesh disconnect: %v\n", err)
		return exitError
	}

	stdout.printf("no session to close\n")
	stdout.printf("\nuse 'nostmesh down' to remove a manually configured tunnel\n")
	return exitOK
}

// loadAllowlist reads authorized peers from configuration.
//
// The allowlist lives in the configuration file rather than a separate store:
// it is operator intent, edited deliberately, and keeping it in one reviewable
// place matters more than the convenience of a mutable store.
func loadAllowlist(cfg config.Config) (*policy.Allowlist, error) {
	allowlist := policy.NewAllowlist()

	for _, authorized := range cfg.Policy.AuthorizedPeers {
		peer, err := domain.ParseNostrPublicKey(authorized.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authorized peer %q: %w", authorized.Alias, err)
		}

		actions := make([]policy.Action, 0, len(authorized.Actions))
		for _, action := range authorized.Actions {
			actions = append(actions, policy.Action(action))
		}

		if err := allowlist.Add(policy.Grant{
			Peer:    peer,
			Alias:   authorized.Alias,
			Actions: actions,
			Revoked: authorized.Revoked,
		}); err != nil {
			return nil, fmt.Errorf("authorized peer %q: %w", authorized.Alias, err)
		}
	}

	return allowlist, nil
}

func joinActions(actions []policy.Action) string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		names = append(names, string(action))
	}
	return strings.Join(names, ", ")
}
