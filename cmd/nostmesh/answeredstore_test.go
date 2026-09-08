package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
)

func answeredSessionID(t *testing.T, seed byte) domain.SessionID {
	t.Helper()

	var id domain.SessionID
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

// What a node answered survives a restart.
//
// This is the whole of #59: the record was memory, so a restarted node forgot
// every session it had answered — and with a durable identity it meets its own
// retained events on the relays and answers them again.
func TestAnsweredSessionsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	session := answeredSessionID(t, 7)

	// The process that answered it.
	before, err := orchestrator.NewAnsweredSessions(clock).WithStore(newAnsweredStore(dir))
	if err != nil {
		t.Fatalf("building the record: %v", err)
	}
	before.Add(session)
	if !before.Contains(session) {
		t.Fatal("the session was not recorded, so this asserts nothing")
	}

	// A new process over the same state directory: what a restart produces.
	after, err := orchestrator.NewAnsweredSessions(clock).WithStore(newAnsweredStore(dir))
	if err != nil {
		t.Fatalf("reloading the record: %v", err)
	}

	if !after.Contains(session) {
		t.Error("a restarted node forgot a session it answered; it will answer the replay")
	}
}

// A node that never ran has answered nothing, and says so without an error.
func TestAFreshNodeHasAnsweredNothing(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

	answered, err := orchestrator.NewAnsweredSessions(clock).WithStore(newAnsweredStore(t.TempDir()))
	if err != nil {
		t.Fatalf("a missing record was reported as an error: %v", err)
	}
	if answered.Contains(answeredSessionID(t, 9)) {
		t.Error("a fresh node claims to have answered a session")
	}
}

// A session old enough to be irrelevant is forgotten.
//
// The record is bounded by the same window that bounds an envelope: a replay of
// something that old fails validation before this check is reached, and keeping
// it forever would grow the file without limit on a node left up for weeks.
func TestOldSessionsAreForgottenOnReload(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	session := answeredSessionID(t, 11)

	before, err := orchestrator.NewAnsweredSessions(func() time.Time { return start }).
		WithStore(newAnsweredStore(dir))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	before.Add(session)

	// A day later, far past any retention an envelope's validity justifies.
	later := start.Add(24 * time.Hour)
	after, err := orchestrator.NewAnsweredSessions(func() time.Time { return later }).
		WithStore(newAnsweredStore(dir))
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}

	if after.Contains(session) {
		t.Error("a session old enough to have expired is still remembered")
	}
}

// A corrupt record is reported rather than silently treated as empty.
//
// Continuing with an empty record would hide why a replay got through, which is
// the question this file exists to answer.
func TestACorruptRecordIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "answered.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	clock := func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }
	if _, err := orchestrator.NewAnsweredSessions(clock).WithStore(newAnsweredStore(dir)); err == nil {
		t.Error("a corrupt record was accepted silently")
	}
}

// The record is written for the service account alone.
func TestTheRecordIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	clock := func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

	answered, err := orchestrator.NewAnsweredSessions(clock).WithStore(newAnsweredStore(dir))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	answered.Add(answeredSessionID(t, 13))

	info, err := os.Stat(filepath.Join(dir, "answered.json"))
	if err != nil {
		t.Fatalf("the record was not written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != answeredFileMode {
		t.Errorf("mode = %o, want %o", mode, answeredFileMode)
	}
}
