package domain

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func nostrKey(t *testing.T, seed byte) NostrPublicKey {
	t.Helper()

	var key NostrPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	if key.IsZero() {
		t.Fatal("test key must not be zero")
	}
	return key
}

func wireGuardKey(t *testing.T, seed byte) WireGuardPublicKey {
	t.Helper()

	var key WireGuardPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func testBinding(t *testing.T, session SessionID, sender, recipient NostrPublicKey, now time.Time) TunnelKeyBinding {
	t.Helper()

	nonce, err := NewNonce(rand.Reader)
	if err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	binding, err := NewTunnelKeyBinding(TunnelKeyBindingParams{
		SessionID: session,
		Sender:    sender,
		Recipient: recipient,
		PublicKey: wireGuardKey(t, 50),
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Nonce:     nonce,
		Sequence:  1,
	})
	if err != nil {
		t.Fatalf("building binding: %v", err)
	}
	return binding
}

// A binding is what turns an authenticated key into an authorized one. Each
// check below is a way an attacker could try to reuse someone else's binding.
func TestBindingValidateFor(t *testing.T) {
	now := testTime()
	local := nostrKey(t, 1)
	peer := nostrKey(t, 100)
	other := nostrKey(t, 200)

	session, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}
	otherSession, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}

	binding := testBinding(t, session, peer, local, now)

	t.Run("accepts the intended context", func(t *testing.T) {
		if err := binding.ValidateFor(session, local, peer, now); err != nil {
			t.Fatalf("expected the binding to validate: %v", err)
		}
	})

	tests := []struct {
		name      string
		session   SessionID
		localNode NostrPublicKey
		peer      NostrPublicKey
		now       time.Time
		wantMsg   string
	}{
		{
			name:      "replayed into another session",
			session:   otherSession,
			localNode: local,
			peer:      peer,
			now:       now,
			wantMsg:   "session",
		},
		{
			name:      "addressed to another node",
			session:   session,
			localNode: other,
			peer:      peer,
			now:       now,
			wantMsg:   "addressed to",
		},
		{
			name:      "from an unexpected peer",
			session:   session,
			localNode: local,
			peer:      other,
			now:       now,
			wantMsg:   "expected peer",
		},
		{
			name:      "past its expiry",
			session:   session,
			localNode: local,
			peer:      peer,
			now:       now.Add(2 * time.Hour),
			wantMsg:   "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := binding.ValidateFor(tt.session, tt.localNode, tt.peer, tt.now)
			if err == nil {
				t.Fatal("expected the binding to be rejected")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error must explain the mismatch (%q), got: %v", tt.wantMsg, err)
			}
		})
	}
}

func TestBindingRequiresEveryField(t *testing.T) {
	now := testTime()
	session, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}
	nonce, err := NewNonce(rand.Reader)
	if err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	complete := TunnelKeyBindingParams{
		SessionID: session,
		Sender:    nostrKey(t, 1),
		Recipient: nostrKey(t, 100),
		PublicKey: wireGuardKey(t, 50),
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Nonce:     nonce,
		Sequence:  1,
	}

	tests := []struct {
		name   string
		mutate func(*TunnelKeyBindingParams)
	}{
		{"no session", func(p *TunnelKeyBindingParams) { p.SessionID = SessionID{} }},
		{"no sender", func(p *TunnelKeyBindingParams) { p.Sender = NostrPublicKey{} }},
		{"no recipient", func(p *TunnelKeyBindingParams) { p.Recipient = NostrPublicKey{} }},
		{"no wireguard key", func(p *TunnelKeyBindingParams) { p.PublicKey = WireGuardPublicKey{} }},
		{"no nonce", func(p *TunnelKeyBindingParams) { p.Nonce = Nonce{} }},
		{"no creation time", func(p *TunnelKeyBindingParams) { p.CreatedAt = time.Time{} }},
		{"no expiry", func(p *TunnelKeyBindingParams) { p.ExpiresAt = time.Time{} }},
		{"expiry before creation", func(p *TunnelKeyBindingParams) { p.ExpiresAt = p.CreatedAt.Add(-time.Second) }},
		{"sender equals recipient", func(p *TunnelKeyBindingParams) { p.Recipient = p.Sender }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := complete
			tt.mutate(&params)

			if _, err := NewTunnelKeyBinding(params); err == nil {
				t.Fatal("an incomplete binding must be rejected")
			}
		})
	}
}

// Attaching a binding validates it against the session, so a binding for a
// different session cannot be installed even by local code that asks nicely.
func TestAttachBindingRejectsMismatch(t *testing.T) {
	now := testTime()
	local := nostrKey(t, 150)
	session := testSession(t)

	otherSession, err := NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}

	wrong := testBinding(t, otherSession, session.Peer().PublicKey(), local, now)
	if err := session.AttachBinding(wrong, local, now); err == nil {
		t.Fatal("a binding for another session must be rejected")
	}
	if session.Binding() != nil {
		t.Error("a rejected binding must not be attached")
	}

	correct := testBinding(t, session.ID(), session.Peer().PublicKey(), local, now)
	if err := session.AttachBinding(correct, local, now); err != nil {
		t.Fatalf("a matching binding must be accepted: %v", err)
	}
	if session.Binding() == nil {
		t.Error("an accepted binding must be attached")
	}
}

func TestAttachBindingRejectedAfterConfiguring(t *testing.T) {
	now := testTime()
	local := nostrKey(t, 150)
	session := testSession(t)

	for _, event := range []SessionEvent{EventConfigure, EventEstablished} {
		if err := session.Apply(event, now); err != nil {
			t.Fatalf("preparing with %s: %v", event, err)
		}
	}

	binding := testBinding(t, session.ID(), session.Peer().PublicKey(), local, now)
	if err := session.AttachBinding(binding, local, now); err == nil {
		t.Fatal("a binding must not be attachable to an established session")
	}
}

func TestAttachBindingRejectedWhenSessionExpired(t *testing.T) {
	local := nostrKey(t, 150)
	session := testSession(t)

	expired := session.ExpiresAt().Add(time.Second)
	binding := testBinding(t, session.ID(), session.Peer().PublicKey(), local, expired)

	if err := session.AttachBinding(binding, local, expired); err == nil {
		t.Fatal("a binding must not attach to an expired session")
	}
}

// Identities render without secrets, since they end up in log lines.
func TestIdentityStringsCarryNoSecret(t *testing.T) {
	private := testNostrPrivate(t)
	identity, err := NewNodeIdentity(nostrKey(t, 1), private, testTime())
	if err != nil {
		t.Fatalf("building identity: %v", err)
	}

	raw, err := private.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}

	rendered := identity.String()
	if strings.Contains(rendered, hex.EncodeToString(raw[:8])) {
		t.Errorf("identity rendering must not contain key material: %s", rendered)
	}
	if strings.Contains(rendered, string(raw)) {
		t.Errorf("identity rendering must not contain raw key bytes: %s", rendered)
	}
}

func TestParseKeysRejectBadInput(t *testing.T) {
	t.Run("nostr", func(t *testing.T) {
		for _, input := range []string{"", "zz", strings.Repeat("0", 64), strings.Repeat("ab", 16)} {
			if _, err := ParseNostrPublicKey(input); err == nil {
				t.Errorf("input %q must be rejected", input)
			}
		}
	})

	t.Run("wireguard", func(t *testing.T) {
		for _, input := range []string{"", "not base64!", "c2hvcnQ="} {
			if _, err := ParseWireGuardPublicKey(input); err == nil {
				t.Errorf("input %q must be rejected", input)
			}
		}
	})
}
