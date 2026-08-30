package domain

import (
	"errors"
	"fmt"
	"time"
)

// SessionState is the lifecycle stage of a session.
//
// MVP 0 configures tunnels manually, so this is the reduced set: the signaling
// states of the full protocol arrive with the Nostr control plane in MVP 1.
type SessionState uint8

const (
	// StateIdle is the initial state. Nothing has been applied to the host.
	StateIdle SessionState = iota

	// StateConfiguring means network changes are being applied. A session that
	// fails here may have partial state, so the transactional journal must be
	// consulted before concluding anything about the host.
	StateConfiguring

	// StateEstablished means the tunnel is confirmed locally. It is never
	// entered because a peer said so: only local verification establishes it.
	StateEstablished

	// StateClosing means the session is being torn down and its effects
	// reverted.
	StateClosing

	// StateClosed is terminal. A closed session never reopens; continuing
	// requires a new session id and new tunnel keys.
	StateClosed

	// StateFailed is terminal. The session ended abnormally and carries the
	// reason for diagnosis.
	StateFailed
)

var stateNames = map[SessionState]string{
	StateIdle:        "IDLE",
	StateConfiguring: "CONFIGURING",
	StateEstablished: "ESTABLISHED",
	StateClosing:     "CLOSING",
	StateClosed:      "CLOSED",
	StateFailed:      "FAILED",
}

// String returns the state name.
func (s SessionState) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("SessionState(%d)", uint8(s))
}

// IsTerminal reports whether the state can never transition again.
func (s SessionState) IsTerminal() bool {
	return s == StateClosed || s == StateFailed
}

// SessionEvent is something that may cause a state transition.
type SessionEvent uint8

const (
	// EventConfigure begins applying the tunnel.
	EventConfigure SessionEvent = iota

	// EventEstablished reports that the tunnel was verified locally.
	EventEstablished

	// EventClose requests an orderly teardown.
	EventClose

	// EventClosed reports that teardown finished and effects were reverted.
	EventClosed

	// EventFail reports an unrecoverable error.
	EventFail

	// EventExpire reports that the session outlived its validity window.
	EventExpire
)

var eventNames = map[SessionEvent]string{
	EventConfigure:   "configure",
	EventEstablished: "established",
	EventClose:       "close",
	EventClosed:      "closed",
	EventFail:        "fail",
	EventExpire:      "expire",
}

// String returns the event name.
func (e SessionEvent) String() string {
	if name, ok := eventNames[e]; ok {
		return name
	}
	return fmt.Sprintf("SessionEvent(%d)", uint8(e))
}

var (
	// ErrInvalidTransition reports an event that the current state does not
	// accept. The session is left untouched.
	ErrInvalidTransition = errors.New("invalid state transition")

	// ErrSessionTerminal reports an attempt to act on a finished session.
	ErrSessionTerminal = errors.New("session is in a terminal state")

	// ErrSessionExpired reports a session past its validity window.
	ErrSessionExpired = errors.New("session has expired")
)

// transitions is the complete transition table. An event absent from the entry
// for a state is rejected: the machine is closed, so an unlisted pair is not an
// oversight but a deliberate refusal.
var transitions = map[SessionState]map[SessionEvent]SessionState{
	StateIdle: {
		EventConfigure: StateConfiguring,
		EventClose:     StateClosed,
		EventFail:      StateFailed,
		EventExpire:    StateFailed,
	},
	StateConfiguring: {
		EventEstablished: StateEstablished,
		EventClose:       StateClosing,
		EventFail:        StateFailed,
		EventExpire:      StateFailed,
	},
	StateEstablished: {
		EventClose:  StateClosing,
		EventFail:   StateFailed,
		EventExpire: StateClosing,
	},
	StateClosing: {
		EventClosed: StateClosed,
		EventFail:   StateFailed,
	},
	// Terminal states accept nothing.
	StateClosed: {},
	StateFailed: {},
}

// Session tracks one tunnel through its lifecycle.
//
// It is a pure value: it decides transitions but applies nothing. Effects on
// the host are the orchestrator's business, carried out by adapters.
type Session struct {
	id        SessionID
	peer      PeerIdentity
	state     SessionState
	createdAt time.Time
	expiresAt time.Time
	updatedAt time.Time
	binding   *TunnelKeyBinding
	failure   string
}

// NewSession creates a session in StateIdle.
func NewSession(id SessionID, peer PeerIdentity, now time.Time, lifetime time.Duration) (*Session, error) {
	if id.IsZero() {
		return nil, errors.New("session requires an id")
	}
	if peer.PublicKey().IsZero() {
		return nil, errors.New("session requires a peer identity")
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("session lifetime must be positive, got %s", lifetime)
	}

	return &Session{
		id:        id,
		peer:      peer,
		state:     StateIdle,
		createdAt: now,
		updatedAt: now,
		expiresAt: now.Add(lifetime),
	}, nil
}

// ID returns the session identifier.
func (s *Session) ID() SessionID { return s.id }

// Peer returns the remote identity.
func (s *Session) Peer() PeerIdentity { return s.peer }

// State returns the current state.
func (s *Session) State() SessionState { return s.state }

// CreatedAt returns when the session was created.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// UpdatedAt returns when the session last transitioned.
func (s *Session) UpdatedAt() time.Time { return s.updatedAt }

// ExpiresAt returns when the session stops being valid.
func (s *Session) ExpiresAt() time.Time { return s.expiresAt }

// FailureReason returns why the session failed, or an empty string.
func (s *Session) FailureReason() string { return s.failure }

// Binding returns the tunnel key binding, or nil if none was attached.
func (s *Session) Binding() *TunnelKeyBinding { return s.binding }

// IsExpired reports whether the session has outlived its validity window.
func (s *Session) IsExpired(now time.Time) bool {
	return !now.Before(s.expiresAt)
}

// Apply attempts a transition.
//
// On success the session moves to the new state. On failure it is left exactly
// as it was: an invalid transition produces an error and no effect, so a
// misbehaving peer cannot nudge a session into an unintended state by sending
// an event out of order.
func (s *Session) Apply(event SessionEvent, now time.Time) error {
	if s.state.IsTerminal() {
		return fmt.Errorf("%w: %s cannot accept %s", ErrSessionTerminal, s.state, event)
	}

	allowed, ok := transitions[s.state]
	if !ok {
		return fmt.Errorf("%w: unknown state %s", ErrInvalidTransition, s.state)
	}

	next, ok := allowed[event]
	if !ok {
		return fmt.Errorf("%w: %s does not accept %s", ErrInvalidTransition, s.state, event)
	}

	s.state = next
	s.updatedAt = now
	return nil
}

// Fail moves the session to StateFailed and records why.
func (s *Session) Fail(reason string, now time.Time) error {
	if err := s.Apply(EventFail, now); err != nil {
		return err
	}
	s.failure = reason
	return nil
}

// AttachBinding records the tunnel key binding for this session.
//
// The binding is validated against the session before it is accepted, so a
// binding issued for a different session or already expired cannot be attached.
// Bindings are only meaningful while the session is being configured.
func (s *Session) AttachBinding(binding TunnelKeyBinding, localNode NostrPublicKey, now time.Time) error {
	if s.state != StateIdle && s.state != StateConfiguring {
		return fmt.Errorf("%w: cannot attach a binding in state %s", ErrInvalidTransition, s.state)
	}
	if s.IsExpired(now) {
		return fmt.Errorf("%w: session %s expired at %s", ErrSessionExpired, s.id.Short(), s.expiresAt.Format(time.RFC3339))
	}

	if err := binding.ValidateFor(s.id, localNode, s.peer.PublicKey(), now); err != nil {
		return fmt.Errorf("rejecting tunnel key binding: %w", err)
	}

	s.binding = &binding
	s.updatedAt = now
	return nil
}

// String renders the session for logs, without secret material.
func (s *Session) String() string {
	return fmt.Sprintf("Session{id: %s, peer: %s, state: %s}",
		s.id.Short(), s.peer.PublicKey().Short(), s.state)
}
