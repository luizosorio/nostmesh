package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A responder that waits and hears nothing gives the attempt back.
//
// Both ends of a pair are willing to answer, and resolveRole settles which one
// normally opens. After both sides lose a session at once, each returns to its
// role and the responder waits — and if the other side is not calling, nobody
// is. Observed between two real hosts: both sat in this wait, and restarting
// one did not help, because the other never came back to notice.
func TestAResponderStopsWaitingWhenNobodyCalls(t *testing.T) {
	driver, _, _, _, peer := newDriverFixture(t, true)

	// As the service runs it: no handshake bound at all, so the only thing that
	// can end this wait is the wait's own.
	driver.options.HandshakeTimeout = Unbounded
	driver.options.RequestWait = 50 * time.Millisecond

	// The receiver has no scripted messages, so it behaves like a peer that
	// went silent.
	err := driver.Connect(context.Background(), peer, RoleResponder)

	if !errors.Is(err, ErrNoRequest) {
		t.Errorf("expected ErrNoRequest so the caller can take the other role, got: %v", err)
	}
}

// The caller's own cancellation stays itself.
//
// Shutdown and revocation cancel the worker, and that must not be reported as
// "nobody called" — the caller would answer it by opening a session while the
// service is stopping.
func TestCancellingAResponderIsNotMistakenForSilence(t *testing.T) {
	driver, _, _, _, peer := newDriverFixture(t, true)
	driver.options.HandshakeTimeout = Unbounded
	driver.options.RequestWait = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := driver.Connect(ctx, peer, RoleResponder)

	if errors.Is(err, ErrNoRequest) {
		t.Error("cancellation was reported as nobody calling")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected cancellation, got: %v", err)
	}
}

// A wait of zero or less means no bound, for callers that want one attempt to
// last as long as they do.
func TestAnUnboundedResponderWaitsForItsCaller(t *testing.T) {
	driver, _, _, _, peer := newDriverFixture(t, true)
	driver.options.HandshakeTimeout = Unbounded
	driver.options.RequestWait = Unbounded

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	err := driver.Connect(ctx, peer, RoleResponder)

	if errors.Is(err, ErrNoRequest) {
		t.Error("an unbounded wait ended on its own")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the caller's own deadline, got: %v", err)
	}
}
