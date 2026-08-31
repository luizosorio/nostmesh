package main

import (
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/protocol"
)

// An unbound plane must not adopt a session on its own.
//
// A relay answers a new subscription with its stored backlog, so the first
// envelope to arrive is routinely from a session the peer has already
// abandoned. A plane that bound itself to it would settle the conversation
// before the driver — which is the only party that can compare the candidates —
// had seen any of the alternatives.
//
// This is the failure observed against real relays: the responder answered a
// stale session while the initiator was running a different one, and both waited
// out their timeouts.
func TestAnUnboundPlaneDoesNotAdoptASession(t *testing.T) {
	plane := &controlPlane{}

	stale := protocol.Envelope{SessionID: strings.Repeat("11", 32)}
	live := protocol.Envelope{SessionID: strings.Repeat("22", 32)}

	if err := plane.matchesSession(stale); err != nil {
		t.Fatalf("an unbound plane must accept the first message: %v", err)
	}

	// The second, from a different session, must also be accepted: an unbound
	// plane is still choosing, and rejecting here would hide the live session
	// behind whichever the relay replayed first.
	if err := plane.matchesSession(live); err != nil {
		t.Fatalf("an unbound plane adopted the first session it saw: %v", err)
	}
}

// Once bound, a message from any other session is refused. That is what stops a
// relay's replay of an older session from being answered as though it were
// current.
func TestABoundPlaneRefusesAForeignSession(t *testing.T) {
	plane := &controlPlane{}

	mine := strings.Repeat("22", 32)
	if err := plane.BindSession(mine); err != nil {
		t.Fatalf("binding: %v", err)
	}

	if err := plane.matchesSession(protocol.Envelope{SessionID: mine}); err != nil {
		t.Errorf("a message from the bound session must be accepted: %v", err)
	}

	err := plane.matchesSession(protocol.Envelope{SessionID: strings.Repeat("11", 32)})
	if err == nil {
		t.Error("a message from another session must be refused once bound")
	}
}

// Binding to nothing must be refused. "Not yet bound" is the plane's initial
// state, not a request a caller makes: accepting one would publish messages
// naming no session, which a peer discards as belonging to no conversation.
func TestBindingAnEmptySessionIsRefused(t *testing.T) {
	plane := &controlPlane{}

	if err := plane.BindSession(""); err == nil {
		t.Error("binding an empty session must be refused")
	}
}
