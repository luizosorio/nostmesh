package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
)

// testService builds a service over a configuration written to disk.
func testService(t *testing.T, cfg config.Config, path string) *service {
	t.Helper()

	return &service{
		cfg:      cfg,
		log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		self:     testNostrKey(t, 1),
		config:   path,
		workers:  make(map[domain.NostrPublicKey]*peerWorker),
		answered: orchestrator.NewAnsweredSessions(time.Now),
	}
}

func testNostrKey(t *testing.T, seed byte) domain.NostrPublicKey {
	t.Helper()

	var key domain.NostrPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

// writeServiceConfig writes a configuration naming one peer, and returns its path.
func writeServiceConfig(t *testing.T, peer domain.NostrPublicKey, revoked bool) (config.Config, string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "nostmesh.json")

	raw := map[string]any{
		"node": map[string]any{
			"name":            "test",
			"state_dir":       dir,
			"overlay_address": "100.96.0.1/32",
			"listen_port":     51820,
			"relays":          []string{"wss://relay.invalid"},
		},
		"log": map[string]any{"level": "error", "format": "text"},
		"policy": map[string]any{
			"default_action": "deny",
			"max_sessions":   8,
			"authorized_peers": []map[string]any{{
				"public_key":  peer.String(),
				"alias":       "test-peer",
				"actions":     []string{"session"},
				"allowed_ips": []string{"100.96.0.2/32"},
				"revoked":     revoked,
			}},
		},
		"peers": []any{},
	}

	encoded, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatalf("encoding config: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	return cfg, path
}

// A revoked peer must lose its worker. While one runs, this node is still
// trying to hold a session with a peer whose authorization was withdrawn.
func TestRevocationStopsTheWorker(t *testing.T) {
	peer := testNostrKey(t, 9)
	cfg, path := writeServiceConfig(t, peer, false)

	svc := testService(t, cfg, path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.reconcile(ctx, cfg); err != nil {
		t.Fatalf("starting: %v", err)
	}
	if !svc.serving(peer) {
		t.Fatal("an authorized peer must get a worker")
	}

	revoked, _ := writeServiceConfig(t, peer, true)
	if err := svc.reconcile(ctx, revoked); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	if svc.serving(peer) {
		t.Error("a revoked peer still has a worker; this node keeps trying to reach it")
	}
}

// A peer removed from the configuration entirely is revoked as surely as one
// marked revoked. Both mean the operator withdrew the authorization.
func TestRemovingAPeerStopsItsWorker(t *testing.T) {
	peer := testNostrKey(t, 9)
	cfg, path := writeServiceConfig(t, peer, false)

	svc := testService(t, cfg, path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.reconcile(ctx, cfg); err != nil {
		t.Fatalf("starting: %v", err)
	}

	// A configuration naming nobody.
	empty := cfg
	empty.Policy.AuthorizedPeers = nil

	if err := svc.reconcile(ctx, empty); err != nil {
		t.Fatalf("reconciling: %v", err)
	}
	if svc.serving(peer) {
		t.Error("a peer removed from the configuration still has a worker")
	}
}

// Reloading must not disturb a peer it did not change. A healthy tunnel
// surviving an unrelated edit is the whole point of reloading rather than
// restarting.
func TestReloadLeavesAnUnchangedPeerAlone(t *testing.T) {
	peer := testNostrKey(t, 9)
	cfg, path := writeServiceConfig(t, peer, false)

	svc := testService(t, cfg, path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.reconcile(ctx, cfg); err != nil {
		t.Fatalf("starting: %v", err)
	}

	svc.mu.Lock()
	before := svc.workers[peer]
	svc.mu.Unlock()

	if err := svc.reconcile(ctx, cfg); err != nil {
		t.Fatalf("reloading: %v", err)
	}

	svc.mu.Lock()
	after := svc.workers[peer]
	svc.mu.Unlock()

	if before != after {
		t.Error("an unchanged peer's worker was replaced; a healthy tunnel would have dropped")
	}
}

// An invalid configuration must be discarded, not applied. Failing open here
// would lose the allowlist to a typo, which is worse than refusing to reload.
func TestAnInvalidReloadKeepsTheRunningConfiguration(t *testing.T) {
	peer := testNostrKey(t, 9)
	cfg, path := writeServiceConfig(t, peer, false)

	svc := testService(t, cfg, path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.reconcile(ctx, cfg); err != nil {
		t.Fatalf("starting: %v", err)
	}

	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("corrupting config: %v", err)
	}

	svc.reload(ctx)

	if !svc.serving(peer) {
		t.Error("an invalid reload emptied the allowlist; a typo must not revoke every peer")
	}
}

// Node-level settings are not reloadable, and the operator must be told rather
// than left believing a change took effect.
func TestNodeSettingsAreReportedAsNotReloadable(t *testing.T) {
	peer := testNostrKey(t, 9)
	before, _ := writeServiceConfig(t, peer, false)

	after := before
	after.Node.ListenPort = 51999
	after.Node.Relays = []string{"wss://other.invalid"}

	changed := nodeSettingsChanged(before, after)

	if len(changed) != 2 {
		t.Fatalf("reported %v, expected listen_port and relays", changed)
	}
	if !strings.Contains(strings.Join(changed, ","), "listen_port") {
		t.Error("a changed listen port was not reported")
	}
	if !strings.Contains(strings.Join(changed, ","), "relays") {
		t.Error("a changed relay set was not reported")
	}
}

// The same configuration must report nothing changed, or every reload would
// warn about settings the operator never touched.
func TestUnchangedNodeSettingsReportNothing(t *testing.T) {
	peer := testNostrKey(t, 9)
	cfg, _ := writeServiceConfig(t, peer, false)

	if changed := nodeSettingsChanged(cfg, cfg); len(changed) != 0 {
		t.Errorf("an unchanged configuration reported %v", changed)
	}
}
