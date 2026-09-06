package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// forbidden lists a value and the encodings it might be recognised in.
//
// Testing one encoding is how a leak in another survives: a key rendered as
// base64 is invisible to a scan that only looks for hex, and both are things a
// struct tag or a formatting verb can produce.
func forbidden(label string, raw []byte) map[string]string {
	return map[string]string{
		label + " (raw)":       string(raw),
		label + " (hex)":       hex.EncodeToString(raw),
		label + " (base64)":    base64.StdEncoding.EncodeToString(raw),
		label + " (base64url)": base64.RawURLEncoding.EncodeToString(raw),
	}
}

// secretsOf collects everything a full run must never write.
func secretsOf(t *testing.T, harness *Harness) map[string]string {
	t.Helper()

	secrets := map[string]string{}

	for label, key := range map[string][]byte{
		"alice's nostr private key":     mustBytes(t, harness.Alice.Private),
		"bob's nostr private key":       mustBytes(t, harness.Bob.Private),
		"alice's wireguard private key": mustBytes(t, harness.Alice.TunnelPrivate),
		"bob's wireguard private key":   mustBytes(t, harness.Bob.TunnelPrivate),
	} {
		for encoding, value := range forbidden(label, key) {
			secrets[encoding] = value
		}
	}

	// The private addresses the run actually used. The operations documentation
	// gates these behind an explicit diagnostic mode, and this run does not
	// enable one.
	secrets["alice's address"] = harness.Alice.Address.Addr().String()
	secrets["bob's address"] = harness.Bob.Address.Addr().String()

	return secrets
}

// A full run at debug writes no secret and no private address.
//
// This is the end-to-end form of the guarantee each package asserts for itself.
// A per-package test proves a constructor redacts; only a run proves that the
// components, wired together and logging at their most verbose, do not between
// them produce a line nobody checked.
//
// What it covers is bounded by what the harness drives, and that is worth being
// precise about rather than leaving to be discovered. The harness builds
// handshakes, a codec and a connectivity engine directly, so this exercises the
// engine's records — including the address gate, which is the piece most likely
// to leak. It does not exercise the driver, the relay client or the network
// journal, because the harness does not use them. Widening it means widening the
// harness, which is its own change.
func TestAFullRunWritesNoSecrets(t *testing.T) {
	var captured bytes.Buffer

	harness, err := NewHarness(HarnessOptions{
		RelayCount: 3,
		Clock:      testClock(),

		// Debug, because the question is what the most verbose setting writes.
		// The diagnostic gate stays closed, which is the default a node runs
		// with.
		Logger: slog.New(slog.NewJSONHandler(&captured, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("building harness: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := harness.Connect(ctx)
	if !result.Established {
		t.Fatalf("connection failed in phase %s: %v", result.Phase, result.Err)
	}

	// A scan over an empty transcript would pass while proving nothing.
	if captured.Len() == 0 {
		t.Fatal("the run logged nothing at debug, so this scan proves nothing about what it writes")
	}

	for label, secret := range secretsOf(t, harness) {
		if strings.Contains(captured.String(), secret) {
			t.Errorf("the transcript contains %s", label)
		}
	}
}

// The scan finds a secret that is genuinely present.
//
// Without this the test above is unfalsifiable: a scan that matches nothing
// passes against every input, and would keep passing after a redaction was
// removed. This plants the leak the guard exists to catch and requires it to be
// reported.
func TestTheRunScanDetectsAPlantedSecret(t *testing.T) {
	var captured bytes.Buffer

	harness, err := NewHarness(HarnessOptions{RelayCount: 3, Clock: testClock()})
	if err != nil {
		t.Fatalf("building harness: %v", err)
	}

	// Written the way a struct tag or a formatting verb would.
	logger := slog.New(slog.NewJSONHandler(&captured, nil))
	logger.Info("a record carrying key material",
		"leaked", hex.EncodeToString(mustBytes(t, harness.Alice.TunnelPrivate)),
		"address", harness.Bob.Address.Addr().String())

	var found int
	for _, secret := range secretsOf(t, harness) {
		if strings.Contains(captured.String(), secret) {
			found++
		}
	}

	if found == 0 {
		t.Error("the scan missed a secret written straight into a record, so it proves nothing about the transcripts that pass")
	}
}

// mustBytes reads raw key material for the scan to hunt for.
func mustBytes[K interface{ Bytes() ([]byte, error) }](t *testing.T, key K) []byte {
	t.Helper()

	raw, err := key.Bytes()
	if err != nil {
		t.Fatalf("reading key material: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("a key read as empty, so the scan would pass against anything")
	}
	return raw
}
