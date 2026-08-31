package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/nostr"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// runRelayCheck verifies behaviour against real Nostr relays.
//
// It is manual and never part of the test suite. The mandatory tests use
// simulated relays because they need a relay that drops and reorders on demand;
// this checks what simulation cannot: whether a real relay accepts the
// experimental kind, what it does with the message size, and what latency looks
// like.
//
// It publishes to public infrastructure, which is permanent and observable, so
// it generates a throwaway identity rather than using the node's own.
func runRelayCheck(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("relay-check", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	relayList := flags.String("relays", "", "comma-separated relay URLs (required)")
	timeout := flags.Duration("timeout", 15*time.Second, "per-relay timeout")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh relay-check --relays wss://a,wss://b\n\n" +
			"Check whether real relays accept this protocol's events.\n\n" +
			"This publishes to public infrastructure. Anything published there is\n" +
			"permanent and observable, so a throwaway identity is generated for the\n" +
			"check and discarded afterwards — the node's own identity is never used.\n\n" +
			"Not part of the test suite: the mandatory tests use simulated relays,\n" +
			"which can fail on demand in ways a real relay cannot.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *relayList == "" {
		stderr.printf("nostmesh relay-check: --relays is required\n")
		return exitUsage
	}

	relays := splitPrefixes(*relayList)
	if len(relays) == 0 {
		stderr.printf("nostmesh relay-check: no relays given\n")
		return exitUsage
	}

	// A throwaway identity, generated here and never stored. Publishing with
	// the node's real identity would tell every relay operator that this node
	// exists, permanently.
	private, public, err := throwawayIdentity()
	if err != nil {
		stderr.printf("nostmesh relay-check: %v\n", err)
		return exitError
	}

	stdout.printf("checking %d relay(s) with a throwaway identity (%s)\n\n",
		len(relays), public.Short())

	failures := 0
	for _, relay := range relays {
		if !checkOneRelay(relay, *timeout, private, public, stdout) {
			failures++
		}
	}

	stdout.printf("\n%d relay(s) checked, %d problem(s)\n", len(relays), failures)
	if failures == len(relays) {
		return exitError
	}
	return exitOK
}

// checkOneRelay reports what one relay does with a protocol event.
func checkOneRelay(url string, timeout time.Duration,
	private domain.NostrPrivateKey, public domain.NostrPublicKey, stdout *output,
) bool {
	stdout.printf("%s\n", url)

	relay, err := nostr.NewWebSocketRelay(nostr.WebSocketRelayOptions{URL: url})
	if err != nil {
		stdout.printf("  ✗ %v\n", err)
		return false
	}
	defer func() { _ = relay.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started := time.Now()
	if err := relay.Connect(ctx); err != nil {
		stdout.printf("  ✗ connect: %v\n", err)
		return false
	}
	stdout.printf("  ✓ connected in %s\n", time.Since(started).Round(time.Millisecond))

	event, err := probeEvent(private, public)
	if err != nil {
		stdout.printf("  ✗ building probe event: %v\n", err)
		return false
	}

	started = time.Now()
	err = relay.Publish(ctx, "relay-check-probe", event)
	elapsed := time.Since(started).Round(time.Millisecond)

	if err != nil {
		// A refusal is informative, not a failure of the check: it tells the
		// operator this relay will not carry the experimental kind.
		stdout.printf("  ! rejected after %s: %v\n", elapsed, err)
		stdout.printf("    this relay will not carry kind %d\n", protocol.ExperimentalKind)
		return false
	}

	stdout.printf("  ✓ accepted kind %d in %s\n", protocol.ExperimentalKind, elapsed)
	stdout.printf("  ✓ event size %d bytes within limits\n", len(event))
	return true
}

// throwawayIdentity generates an identity used only for this check.
func throwawayIdentity() (domain.NostrPrivateKey, domain.NostrPublicKey, error) {
	raw := make([]byte, domain.NostrKeySize)
	if _, err := rand.Read(raw); err != nil {
		return domain.NostrPrivateKey{}, domain.NostrPublicKey{}, fmt.Errorf("generating throwaway key: %w", err)
	}

	private, err := domain.NewNostrPrivateKey(raw)
	if err != nil {
		return domain.NostrPrivateKey{}, domain.NostrPublicKey{}, err
	}

	public, err := nostr.DerivePublicKey(private)
	if err != nil {
		return domain.NostrPrivateKey{}, domain.NostrPublicKey{}, err
	}
	return private, public, nil
}

// probeEvent builds a properly signed NIP-01 event carrying the experimental
// kind.
//
// It has to be genuinely valid — signed, with a correctly computed id — or a
// relay refusing it would say nothing about whether it accepts the kind. An
// unsigned event is rejected by every relay for the same reason, which would
// make the check measure nothing.
//
// It carries the same tags a real control message carries, including the d tag
// the experimental kind requires: a relay may treat a parameterized-replaceable
// event without one differently, and a check that omitted it would not be
// checking what this protocol actually publishes.
func probeEvent(private domain.NostrPrivateKey, public domain.NostrPublicKey) ([]byte, error) {
	signer, err := nostr.NewSigner(private)
	if err != nil {
		return nil, fmt.Errorf("building signer: %w", err)
	}

	tags := [][]string{
		nostr.RecipientTag(public),
		nostr.ReplaceableTag("relay-check", string(protocol.TypeSessionRequest), 1),
	}

	_, raw, err := nostr.BuildEvent(signer, protocol.ExperimentalKind, tags, "nostmesh relay check", time.Now())
	if err != nil {
		return nil, err
	}
	return raw, nil
}
