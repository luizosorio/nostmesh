package domain

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func testTime() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

func testPeer(t *testing.T) PeerIdentity {
	t.Helper()

	var key NostrPublicKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	peer, err := NewPeerIdentity(key, "lab-peer")
	if err != nil {
		t.Fatalf("building peer: %v", err)
	}
	return peer
}

func testSession(t *testing.T) *Session {
	t.Helper()

	id, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}
	session, err := NewSession(id, testPeer(t), testTime(), time.Hour)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return session
}

func TestSessionStartsIdle(t *testing.T) {
	session := testSession(t)

	if session.State() != StateIdle {
		t.Errorf("state = %s, want IDLE", session.State())
	}
	if session.Binding() != nil {
		t.Error("a new session must not carry a binding")
	}
}

func TestSessionHappyPath(t *testing.T) {
	session := testSession(t)
	now := testTime()

	steps := []struct {
		event SessionEvent
		want  SessionState
	}{
		{EventConfigure, StateConfiguring},
		{EventEstablished, StateEstablished},
		{EventClose, StateClosing},
		{EventClosed, StateClosed},
	}

	for _, step := range steps {
		now = now.Add(time.Second)
		if err := session.Apply(step.event, now); err != nil {
			t.Fatalf("applying %s: %v", step.event, err)
		}
		if session.State() != step.want {
			t.Fatalf("after %s state = %s, want %s", step.event, session.State(), step.want)
		}
	}

	if !session.State().IsTerminal() {
		t.Error("CLOSED must be terminal")
	}
}

// An invalid transition must leave the session exactly as it was. A peer
// sending events out of order must not be able to nudge state.
func TestInvalidTransitionHasNoEffect(t *testing.T) {
	tests := []struct {
		name    string
		prepare []SessionEvent
		invalid SessionEvent
	}{
		{"establish before configuring", nil, EventEstablished},
		{"closed before closing", nil, EventClosed},
		{"configure twice", []SessionEvent{EventConfigure}, EventConfigure},
		{"establish twice", []SessionEvent{EventConfigure, EventEstablished}, EventEstablished},
		{"configure after established", []SessionEvent{EventConfigure, EventEstablished}, EventConfigure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := testSession(t)
			now := testTime()

			for _, event := range tt.prepare {
				if err := session.Apply(event, now); err != nil {
					t.Fatalf("preparing with %s: %v", event, err)
				}
			}

			stateBefore := session.State()
			updatedBefore := session.UpdatedAt()

			err := session.Apply(tt.invalid, now.Add(time.Hour))
			if err == nil {
				t.Fatalf("%s must be rejected in state %s", tt.invalid, stateBefore)
			}
			if !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("expected ErrInvalidTransition, got: %v", err)
			}
			if session.State() != stateBefore {
				t.Errorf("state changed to %s despite the error", session.State())
			}
			if !session.UpdatedAt().Equal(updatedBefore) {
				t.Error("updatedAt changed despite the rejected transition")
			}
		})
	}
}

// Terminal states never reopen. Continuing requires a new session id and new
// tunnel keys, which is what stops an old key from reviving a closed session.
func TestTerminalStatesAcceptNothing(t *testing.T) {
	for _, terminal := range []struct {
		name    string
		prepare []SessionEvent
	}{
		{"closed", []SessionEvent{EventConfigure, EventEstablished, EventClose, EventClosed}},
		{"failed", []SessionEvent{EventFail}},
	} {
		t.Run(terminal.name, func(t *testing.T) {
			session := testSession(t)
			now := testTime()

			for _, event := range terminal.prepare {
				if err := session.Apply(event, now); err != nil {
					t.Fatalf("preparing with %s: %v", event, err)
				}
			}

			for _, event := range []SessionEvent{EventConfigure, EventEstablished, EventClose, EventClosed, EventFail} {
				err := session.Apply(event, now)
				if err == nil {
					t.Errorf("%s must be rejected in %s", event, session.State())
				}
				if !errors.Is(err, ErrSessionTerminal) {
					t.Errorf("expected ErrSessionTerminal for %s, got: %v", event, err)
				}
			}
		})
	}
}

func TestFailRecordsReason(t *testing.T) {
	session := testSession(t)

	if err := session.Fail("handshake timed out", testTime()); err != nil {
		t.Fatalf("failing session: %v", err)
	}
	if session.State() != StateFailed {
		t.Errorf("state = %s, want FAILED", session.State())
	}
	if session.FailureReason() != "handshake timed out" {
		t.Errorf("reason = %q, want the recorded reason", session.FailureReason())
	}
}

func TestSessionExpiry(t *testing.T) {
	session := testSession(t)
	now := testTime()

	if session.IsExpired(now) {
		t.Error("a fresh session must not be expired")
	}
	if session.IsExpired(session.ExpiresAt().Add(-time.Nanosecond)) {
		t.Error("a session must be valid up to its expiry")
	}
	if !session.IsExpired(session.ExpiresAt()) {
		t.Error("a session must be expired at exactly its expiry")
	}
	if !session.IsExpired(now.Add(2 * time.Hour)) {
		t.Error("a session must be expired past its window")
	}
}

// An established session that expires goes to CLOSING, not straight to a
// terminal state: its network effects still have to be reverted.
func TestExpiryFromEstablishedClosesGracefully(t *testing.T) {
	session := testSession(t)
	now := testTime()

	for _, event := range []SessionEvent{EventConfigure, EventEstablished} {
		if err := session.Apply(event, now); err != nil {
			t.Fatalf("preparing with %s: %v", event, err)
		}
	}

	if err := session.Apply(EventExpire, session.ExpiresAt()); err != nil {
		t.Fatalf("expiring session: %v", err)
	}
	if session.State() != StateClosing {
		t.Errorf("state = %s, want CLOSING so effects are reverted", session.State())
	}
}

func TestNewSessionValidation(t *testing.T) {
	id, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}

	t.Run("zero id", func(t *testing.T) {
		if _, err := NewSession(SessionID{}, testPeer(t), testTime(), time.Hour); err == nil {
			t.Error("a zero session id must be rejected")
		}
	})

	t.Run("empty peer", func(t *testing.T) {
		if _, err := NewSession(id, PeerIdentity{}, testTime(), time.Hour); err == nil {
			t.Error("an empty peer must be rejected")
		}
	})

	t.Run("non-positive lifetime", func(t *testing.T) {
		for _, lifetime := range []time.Duration{0, -time.Second} {
			if _, err := NewSession(id, testPeer(t), testTime(), lifetime); err == nil {
				t.Errorf("lifetime %s must be rejected", lifetime)
			}
		}
	})
}
