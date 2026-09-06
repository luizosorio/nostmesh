package netstate

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/luizosorio/nostmesh/internal/observability/observabilitytest"
)

// A successful change reports what it applied.
//
// The journal records the same thing durably, but a transaction file is not what
// an operator reads while watching a node come up.
func TestASuccessfulChangeIsReported(t *testing.T) {
	manager, _, _ := newTestManager(t)
	logger, records := observabilitytest.New(slog.LevelDebug)
	manager.WithLogger(logger)

	ctx := context.Background()
	plan, err := manager.PlanInterface(ctx, "tx-1", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if _, err := manager.Apply(ctx, plan); err != nil {
		t.Fatalf("applying: %v", err)
	}

	applied, found := records.Find("journal.transaction.applied")
	if !found {
		t.Fatalf("a successful change went unreported; events were %v", records.Events())
	}
	if result := applied.Attrs["result"].String(); result != "ok" {
		t.Errorf("result = %q, want ok", result)
	}
	if applied.Level != slog.LevelInfo {
		t.Errorf("a change applied to the host was logged at %v, not info", applied.Level)
	}
}

// A rollback is reported, and reported as a warning.
//
// A host that was changed and then changed back is not a routine event: it means
// something failed partway, and the reason the host looks untouched is that
// compensation ran. An operator who cannot see that has no way to tell it from
// nothing having been attempted.
func TestARollbackIsReported(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	logger, records := observabilitytest.New(slog.LevelDebug)
	manager.WithLogger(logger)

	// The peer fails, so the interface created before it must be compensated.
	controller.FailOn["ApplyPeer"] = errors.New("netlink refused the peer")

	ctx := context.Background()
	plan, err := manager.PlanInterface(ctx, "tx-2", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("a failing apply reported success")
	}

	if _, found := records.Find("journal.transaction.failed"); !found {
		t.Errorf("the failure went unreported; events were %v", records.Events())
	}

	rolledBack, found := records.Find("journal.transaction.rolled_back")
	if !found {
		t.Fatalf("the rollback went unreported; events were %v", records.Events())
	}
	if rolledBack.Level != slog.LevelWarn {
		t.Errorf("a rollback was logged at %v; it is not a routine event", rolledBack.Level)
	}
}

// The failure is reported before compensation runs.
//
// A process that dies during rollback leaves a log ending at the last thing it
// said. If that is the failure, the log names what was being undone, which is
// the state reconciliation has to resolve at the next start. Reporting only
// afterwards would lose exactly the case where it matters most.
func TestTheFailureIsReportedBeforeTheRollback(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	logger, records := observabilitytest.New(slog.LevelDebug)
	manager.WithLogger(logger)

	controller.FailOn["ApplyPeer"] = errors.New("netlink refused the peer")

	ctx := context.Background()
	plan, err := manager.PlanInterface(ctx, "tx-3", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("a failing apply reported success")
	}

	events := records.Events()
	failedAt, rolledBackAt := -1, -1
	for i, event := range events {
		switch event {
		case "journal.transaction.failed":
			failedAt = i
		case "journal.transaction.rolled_back":
			rolledBackAt = i
		}
	}

	if failedAt < 0 || rolledBackAt < 0 {
		t.Fatalf("both events must be present; got %v", events)
	}
	if failedAt > rolledBackAt {
		t.Error("the rollback was reported before the failure that caused it, so a log cut short would not say what was being undone")
	}
}

// A manager without a logger applies changes without panicking.
func TestAManagerWithoutALoggerDoesNotPanic(t *testing.T) {
	manager, _, _ := newTestManager(t)

	if manager.log == nil {
		t.Fatal("the manager's logger is nil, so every record would panic")
	}

	ctx := context.Background()
	plan, err := manager.PlanInterface(ctx, "tx-4", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if _, err := manager.Apply(ctx, plan); err != nil {
		t.Fatalf("applying: %v", err)
	}
}

// WithLogger tolerates a nil logger.
//
// The orchestrator passes whatever it was given, which is nil for a command that
// reports through stdout instead.
func TestWithLoggerToleratesNil(t *testing.T) {
	manager, _, _ := newTestManager(t)
	manager.WithLogger(nil)

	if manager.log == nil {
		t.Error("WithLogger(nil) left the manager without a logger, so every record would panic")
	}
}
