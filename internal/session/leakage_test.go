package session

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The central invariant, checked at the handshake level rather than only on the
// types: the WireGuard private key must not reach an event, a log, a serialized
// structure, or a diagnostic rendering.
//
// The type system already prevents the obvious paths (NM-06). This checks the
// integration: a handshake holds both halves of a key pair, and it would be easy
// to serialize the wrong one.
func TestPrivateKeyNeverLeavesTheHandshake(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	raw, err := initiator.LocalTunnelPrivate().Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}

	// Every encoding an attacker might find the key in.
	forbidden := map[string]string{
		"raw bytes":  string(raw),
		"hex":        hex.EncodeToString(raw),
		"base64":     base64.StdEncoding.EncodeToString(raw),
		"hex prefix": hex.EncodeToString(raw[:8]),
	}

	assertClean := func(t *testing.T, label, content string) {
		t.Helper()

		for encoding, secret := range forbidden {
			if strings.Contains(content, secret) {
				t.Errorf("%s contains the private key as %s", label, encoding)
			}
		}
	}

	// 1. The request that goes on the wire.
	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encoding request: %v", err)
	}
	assertClean(t, "the session request", string(encoded))

	// The public key must be there — otherwise nothing was sent at all.
	if !strings.Contains(string(encoded), initiator.LocalTunnelPublic().String()) {
		t.Error("the request does not carry the tunnel public key")
	}

	// 2. The offer.
	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("receiving request: %v", err)
	}
	offer, _, err := responder.BuildOffer(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building offer: %v", err)
	}
	offerEncoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("encoding offer: %v", err)
	}

	responderRaw, err := responder.LocalTunnelPrivate().Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	if bytes.Contains(offerEncoded, responderRaw) {
		t.Error("the offer contains the responder's private key")
	}

	// 3. Log output, through a real handler rather than an assumption.
	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("handshake progressed",
		"handshake", initiator.String(),
		"tunnel_key", initiator.LocalTunnelPrivate(),
		"state", initiator.State().String(),
	)
	assertClean(t, "the log line", logged.String())

	// 4. Every formatting verb.
	for _, rendered := range []string{
		fmt.Sprintf("%v", initiator),
		fmt.Sprintf("%+v", initiator),
		initiator.String(),
		fmt.Sprintf("%v", initiator.LocalTunnelPrivate()),
		fmt.Sprintf("%#v", initiator.LocalTunnelPrivate()),
	} {
		assertClean(t, "a formatted rendering", rendered)
	}
}

// A struct holding a handshake must fail to encode rather than emit a
// placeholder that looks like data.
func TestSerializingAHandshakeFails(t *testing.T) {
	initiator, _ := pair(t)

	payload := struct {
		Session string `json:"session"`
		Key     any    `json:"key"`
	}{
		Session: initiator.SessionID().Short(),
		Key:     initiator.LocalTunnelPrivate(),
	}

	if _, err := json.Marshal(payload); err == nil {
		t.Error("a structure containing a tunnel private key must fail to encode")
	}
}

// Both sides must generate independent keys. Sharing one would mean both ends
// hold the same private key, which is not a tunnel.
func TestEachSideHoldsItsOwnKey(t *testing.T) {
	initiator, responder := pair(t)

	initiatorRaw, err := initiator.LocalTunnelPrivate().Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	responderRaw, err := responder.LocalTunnelPrivate().Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}

	if bytes.Equal(initiatorRaw, responderRaw) {
		t.Fatal("both sides hold the same private key")
	}
	if initiator.LocalTunnelPublic() == responder.LocalTunnelPublic() {
		t.Error("both sides advertise the same public key")
	}
}

// Error messages reach logs and sometimes peers. They must name what went wrong
// without quoting the payload that caused it.
func TestErrorsDoNotQuotePayloads(t *testing.T) {
	initiator, responder := pair(t)
	now := testNow()

	request, err := initiator.BuildRequest(testNonce(t), 5*time.Minute, now)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if err := responder.ReceiveRequest(*request.Request, 0, allowAll{}, now); err != nil {
		t.Fatalf("receiving request: %v", err)
	}

	// Provoke a substitution error and inspect what it says.
	substituted := request.Request.TunnelKey
	other, _ := tunnelKeyPair(t, 210)
	substituted.PublicKey = other.String()

	err = responder.bindPeerTunnelKey(substituted, now)
	if err == nil {
		t.Fatal("substitution must be refused")
	}

	message := err.Error()

	// Keys are abbreviated in errors, so a log line stays readable and a full
	// key is not echoed back.
	if strings.Contains(message, other.String()) {
		t.Errorf("the error quotes a full key: %s", message)
	}
	if len(message) > 200 {
		t.Errorf("the error is %d characters; it likely embeds a payload", len(message))
	}
}
