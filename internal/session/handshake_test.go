package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

func testNow() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

// allowAll authorizes every peer, so a test can isolate the transition being
// exercised from the policy decision.
type allowAll struct{}

func (allowAll) Authorize(domain.NostrPublicKey) error { return nil }

// denyAll refuses every peer, standing in for deny-by-default policy.
type denyAll struct{}

func (denyAll) Authorize(domain.NostrPublicKey) error {
	return errors.New("not in the allowlist")
}

func nostrKey(t *testing.T, seed byte) domain.NostrPublicKey {
	t.Helper()

	var key domain.NostrPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func tunnelKeyPair(t *testing.T, seed byte) (domain.WireGuardPublicKey, domain.WireGuardPrivateKey) {
	t.Helper()

	raw := make([]byte, domain.WireGuardKeySize)
	for i := range raw {
		raw[i] = seed + byte(i)
	}

	private, err := domain.NewWireGuardPrivateKey(raw)
	if err != nil {
		t.Fatalf("building tunnel key: %v", err)
	}

	var public domain.WireGuardPublicKey
	for i := range public {
		public[i] = seed + byte(i) + 128
	}
	return public, private
}

func testNonce(t *testing.T) domain.Nonce {
	t.Helper()

	nonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		t.Fatalf("generating nonce: %v", err)
	}
	return nonce
}

func testSessionID(t *testing.T) domain.SessionID {
	t.Helper()

	id, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("generating session id: %v", err)
	}
	return id
}

// pair builds both sides of a handshake sharing one session id, as two real
// nodes would.
func pair(t *testing.T) (initiator, responder *Handshake) {
	t.Helper()

	sessionID := testSessionID(t)
	alice := nostrKey(t, 1)
	bob := nostrKey(t, 100)

	alicePublic, alicePrivate := tunnelKeyPair(t, 10)
	bobPublic, bobPrivate := tunnelKeyPair(t, 60)

	var err error
	initiator, err = New(Options{
		Role: RoleInitiator, SessionID: sessionID,
		LocalKey: alice, PeerKey: bob,
		TunnelPublic: alicePublic, TunnelPrivate: alicePrivate,
		Now: testNow(),
	})
	if err != nil {
		t.Fatalf("building initiator: %v", err)
	}

	responder, err = New(Options{
		Role: RoleResponder, SessionID: sessionID,
		LocalKey: bob, PeerKey: alice,
		TunnelPublic: bobPublic, TunnelPrivate: bobPrivate,
		Now: testNow(),
	})
	if err != nil {
		t.Fatalf("building responder: %v", err)
	}
	return initiator, responder
}

// runHandshake drives both sides through request → offer → accept.
func runHandshake(t *testing.T, initiator, responder *Handshake) {
	t.Helper()

	now := testNow()

	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("receiving request: %v", err)
	}

	offer, _, err := responder.BuildOffer(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building offer: %v", err)
	}
	if err := initiator.ReceiveOffer(*offer.Offer, 0, now); err != nil {
		t.Fatalf("receiving offer: %v", err)
	}

	accept, err := initiator.BuildAccept(now)
	if err != nil {
		t.Fatalf("building accept: %v", err)
	}
	if err := responder.ReceiveAccept(*accept.Accept, 1, now); err != nil {
		t.Fatalf("receiving accept: %v", err)
	}
}

func TestFullHandshakeReachesConnecting(t *testing.T) {
	initiator, responder := pair(t)
	runHandshake(t, initiator, responder)

	if initiator.State() != StateConnecting {
		t.Errorf("initiator state = %s, want CONNECTING", initiator.State())
	}
	if responder.State() != StateConnecting {
		t.Errorf("responder state = %s, want CONNECTING", responder.State())
	}
	if initiator.OfferHash() != responder.OfferHash() {
		t.Error("the two sides committed to different terms")
	}
}

// Each side must hold the other's public key and its own private key. Getting
// this backwards would mean encrypting for yourself.
func TestBothSidesBindTheOtherTunnelKey(t *testing.T) {
	initiator, responder := pair(t)
	runHandshake(t, initiator, responder)

	if initiator.PeerTunnelKey() == nil || responder.PeerTunnelKey() == nil {
		t.Fatal("both sides must bind the peer's tunnel key")
	}
	if initiator.PeerTunnelKey().PublicKey != responder.LocalTunnelPublic().String() {
		t.Error("the initiator bound something other than the responder's key")
	}
	if responder.PeerTunnelKey().PublicKey != initiator.LocalTunnelPublic().String() {
		t.Error("the responder bound something other than the initiator's key")
	}
}

// Deny-by-default: a peer absent from local policy is refused, and refusing
// leaves no state behind for it to build on.
func TestUnauthorizedPeerIsRefusedWithoutStateChange(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	err = responder.ReceiveRequest(*request.Request, 0, denyAll{}, now)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}

	if responder.State() != StateIdle {
		t.Errorf("state changed to %s despite refusal", responder.State())
	}
	if responder.PeerTunnelKey() != nil {
		t.Error("a refused peer's tunnel key was bound anyway")
	}
}

// Substituting the tunnel key mid-handshake is how an attacker would take over
// the tunnel. Once bound, a different key is refused.
func TestTunnelKeySubstitutionIsRefused(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("receiving request: %v", err)
	}

	// The attacker replays the request with their own key at a new sequence.
	substituted := *request.Request
	attacker, _ := tunnelKeyPair(t, 200)
	substituted.TunnelKey.PublicKey = attacker.String()

	err = responder.bindPeerTunnelKey(substituted.TunnelKey, now)
	if !errors.Is(err, ErrKeySubstituted) {
		t.Fatalf("expected ErrKeySubstituted, got: %v", err)
	}

	// The originally bound key must still be in place.
	if responder.PeerTunnelKey().PublicKey != request.Request.TunnelKey.PublicKey {
		t.Error("the substituted key replaced the bound one")
	}
}

// A peer offering this node's own tunnel key would mean both ends hold the same
// private key, which is not a tunnel.
func TestOwnKeyOfferedBackIsRefused(t *testing.T) {
	_, responder := pair(t)
	now := testNow()

	reflected := protocol.TunnelKey{
		PublicKey: responder.LocalTunnelPublic().String(),
		Nonce:     testNonce(t).String(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}

	if err := responder.bindPeerTunnelKey(reflected, now); !errors.Is(err, ErrKeySubstituted) {
		t.Errorf("expected ErrKeySubstituted, got: %v", err)
	}
}

// An expired key must not be bound: it was authorized for a window that has
// passed.
func TestExpiredTunnelKeyIsRefused(t *testing.T) {
	_, responder := pair(t)
	now := testNow()

	stale := protocol.TunnelKey{
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 31)) + "A",
		Nonce:     testNonce(t).String(),
		ExpiresAt: now.Add(-time.Hour).Unix(),
	}

	public, _ := tunnelKeyPair(t, 200)
	stale.PublicKey = public.String()

	if err := responder.bindPeerTunnelKey(stale, now); !errors.Is(err, protocol.ErrExpired) {
		t.Errorf("expected ErrExpired, got: %v", err)
	}
}

// Relays deliver duplicates by design, so an identical repeat must be
// idempotent rather than an error.
func TestDuplicateMessageIsIdempotent(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("first delivery: %v", err)
	}

	// The same message at the same sequence, as a second relay would deliver.
	if err := responder.recordSeq(0, *request.Request); err != nil {
		t.Errorf("an identical repeat must be idempotent, got: %v", err)
	}
}

// Different content at the same sequence is not duplication: one of the two
// messages is not what it claims, and ordering can no longer be trusted.
func TestConflictingSequenceIsRefused(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("receiving request: %v", err)
	}

	altered := *request.Request
	altered.OverlayAddress = "10.0.0.99/32"

	if err := responder.recordSeq(0, altered); !errors.Is(err, ErrSequenceConflict) {
		t.Errorf("expected ErrSequenceConflict, got: %v", err)
	}
}

// An acceptance must reference exactly the terms offered. Anything else means
// the peer is accepting something this node never proposed.
func TestAcceptanceOfDifferentTermsIsRefused(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	request, _ := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("receiving request: %v", err)
	}
	if _, _, err := responder.BuildOffer(testNonce(t), 5*time.Minute, now); err != nil {
		t.Fatalf("building offer: %v", err)
	}

	forged := protocol.SessionAccept{OfferHash: strings.Repeat("ab", 32)}

	if err := responder.ReceiveAccept(forged, 1, now); !errors.Is(err, ErrOfferMismatch) {
		t.Errorf("expected ErrOfferMismatch, got: %v", err)
	}
}

// Every out-of-order message must be refused, and refusing must change nothing.
func TestUnexpectedMessagesLeaveStateUntouched(t *testing.T) {
	tests := []struct {
		name string
		act  func(t *testing.T, initiator, responder *Handshake) error
	}{
		{
			name: "offer before request",
			act: func(t *testing.T, i, r *Handshake) error {
				_, _, err := r.BuildOffer(testNonce(t), time.Minute, testNow())
				return err
			},
		},
		{
			name: "accept before offer",
			act: func(t *testing.T, i, r *Handshake) error {
				_, err := i.BuildAccept(testNow())
				return err
			},
		},
		{
			name: "initiator receiving a request",
			act: func(t *testing.T, i, r *Handshake) error {
				return i.ReceiveRequest(protocol.SessionRequest{}, 0, allowAll{}, testNow())
			},
		},
		{
			name: "responder receiving an offer",
			act: func(t *testing.T, i, r *Handshake) error {
				return r.ReceiveOffer(protocol.SessionOffer{}, 0, testNow())
			},
		},
		{
			name: "establishing before connecting",
			act: func(t *testing.T, i, r *Handshake) error {
				return i.ConfirmEstablished(testNow())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator, responder := pair(t)
			initiatorBefore, responderBefore := initiator.State(), responder.State()

			err := tt.act(t, initiator, responder)
			if !errors.Is(err, ErrUnexpectedMessage) {
				t.Fatalf("expected ErrUnexpectedMessage, got: %v", err)
			}

			if initiator.State() != initiatorBefore || responder.State() != responderBefore {
				t.Errorf("state changed despite the refusal: %s/%s",
					initiator.State(), responder.State())
			}
		})
	}
}

// A session becomes established when this node verifies the tunnel. A peer
// saying it is ready is evidence about the peer, not about this host.
func TestPeerReadyDoesNotEstablishSession(t *testing.T) {
	initiator, responder := pair(t)
	runHandshake(t, initiator, responder)

	if err := initiator.ReceiveReady(2, testNow()); err != nil {
		t.Fatalf("receiving ready: %v", err)
	}

	if initiator.State() != StateConnecting {
		t.Errorf("state = %s; a peer's ready must not establish the session", initiator.State())
	}

	if err := initiator.ConfirmEstablished(testNow()); err != nil {
		t.Fatalf("confirming locally: %v", err)
	}
	if initiator.State() != StateEstablished {
		t.Errorf("state = %s, want ESTABLISHED after local confirmation", initiator.State())
	}
}

// A peer that goes silent must not leave a session pending forever.
func TestHandshakeTimesOut(t *testing.T) {
	initiator, _ := pair(t)
	late := testNow().Add(2 * time.Minute)

	_, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, late)
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout, got: %v", err)
	}
}

func TestTerminalStatesAcceptNothing(t *testing.T) {
	for _, terminal := range []struct {
		name  string
		close func(h *Handshake)
	}{
		{"closed", func(h *Handshake) { h.Close(testNow()) }},
		{"failed", func(h *Handshake) { h.Fail("test", testNow()) }},
	} {
		t.Run(terminal.name, func(t *testing.T) {
			initiator, _ := pair(t)
			terminal.close(initiator)

			_, err := initiator.BuildRequest(testNonce(t), time.Minute, testNow())
			if !errors.Is(err, ErrTerminal) {
				t.Errorf("expected ErrTerminal, got: %v", err)
			}
		})
	}
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	valid := Options{
		Role:      RoleInitiator,
		SessionID: testSessionID(t),
		LocalKey:  nostrKey(t, 1),
		PeerKey:   nostrKey(t, 100),
		Now:       testNow(),
	}
	valid.TunnelPublic, valid.TunnelPrivate = tunnelKeyPair(t, 10)

	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"no session id", func(o *Options) { o.SessionID = domain.SessionID{} }},
		{"no local key", func(o *Options) { o.LocalKey = domain.NostrPublicKey{} }},
		{"no peer key", func(o *Options) { o.PeerKey = domain.NostrPublicKey{} }},
		{"same identity both sides", func(o *Options) { o.PeerKey = o.LocalKey }},
		{"no tunnel key", func(o *Options) { o.TunnelPublic = domain.WireGuardPublicKey{} }},
		{"no clock reading", func(o *Options) { o.Now = time.Time{} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := valid
			tt.mutate(&opts)

			if _, err := New(opts); err == nil {
				t.Error("expected the options to be refused")
			}
		})
	}
}

// The handshake ends up in logs, so it must render without secret material.
func TestHandshakeRendersWithoutSecrets(t *testing.T) {
	initiator, _ := pair(t)

	raw, err := initiator.LocalTunnelPrivate().Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}

	rendered := initiator.String()
	if strings.Contains(rendered, string(raw)) {
		t.Errorf("the rendering leaked key material: %s", rendered)
	}
	if strings.Contains(rendered, base64.StdEncoding.EncodeToString(raw)) {
		t.Errorf("the rendering leaked the encoded key: %s", rendered)
	}
}
