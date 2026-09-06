package connectivity

import (
	"context"
	"errors"
	"testing"

	"github.com/luizosorio/nostmesh/internal/observability"
)

// Discovery failures are classified by sentinel, never by message text.
//
// Most of these are ordinary rather than wrong: a node with no PCP router and no
// configured observer fails those methods on every run. The code is what lets an
// operator tell that apart from discovery that is actually broken.
func TestGatherFailuresAreClassified(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want string
	}{
		{"observer unreachable", ErrObserverUnreachable, observability.ReasonObserverUnreachable},
		{"observer lied", ErrObserverResponse, observability.ReasonObserverUnreachable},
		{"unsafe address", ErrUnsafeAddress, observability.ReasonPolicyRefused},
		{"too many", ErrTooManyCandidates, observability.ReasonOversized},
		{"cancelled", context.Canceled, observability.ReasonCancelled},
		{"unclassified", errors.New("something else"), observability.ReasonNoCandidates},
		{"none", nil, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := classifyGatherFailure(testCase.err); got != testCase.want {
				t.Errorf("classifyGatherFailure = %q, want %q", got, testCase.want)
			}
		})
	}
}

// A probe timing out is not the same as one that failed to authenticate.
//
// The first is an ordinary NAT traversal outcome; the second is either the wrong
// peer or a forgery. Reporting them with one code would hide the only case here
// that is a security event.
func TestAnUnauthenticatedProbeIsNotATimeout(t *testing.T) {
	unauthenticated := classifyProbeFailure(ErrUnverified)
	timedOut := classifyProbeFailure(context.DeadlineExceeded)

	if unauthenticated == timedOut {
		t.Error("a probe that failed to authenticate reports the same reason as one that timed out")
	}
	if unauthenticated != observability.ReasonProbeUnauthenticated {
		t.Errorf("an unauthenticated probe reports %q", unauthenticated)
	}
}

// A gatherer built without a logger logs nothing rather than panicking.
func TestAGathererWithoutALoggerDoesNotPanic(t *testing.T) {
	gatherer := NewGatherer(GathererOptions{})

	if gatherer.log == nil {
		t.Fatal("the gatherer's logger is nil, so every record would panic")
	}
	gatherer.Gather(t.Context(), 51820)
}

// An engine built without a logger logs nothing rather than panicking.
func TestAnEngineWithoutALoggerDoesNotPanic(t *testing.T) {
	engine, err := NewEngine(EngineOptions{SessionID: "abc"})
	if err != nil {
		t.Fatalf("building the engine: %v", err)
	}
	if engine.log == nil {
		t.Fatal("the engine's logger is nil, so every record would panic")
	}
}

// The engine defaults to the closed gate.
//
// An engine built without an explicit setting must not disclose addresses: the
// default has to be the safe one, because the opposite mistake is written to
// disk before anyone notices.
func TestAnEngineDefaultsToTheClosedGate(t *testing.T) {
	engine, err := NewEngine(EngineOptions{SessionID: "abc"})
	if err != nil {
		t.Fatalf("building the engine: %v", err)
	}
	if engine.diagnostic != observability.DiagnosticOff {
		t.Error("an engine built without a diagnostic setting discloses addresses")
	}
}
