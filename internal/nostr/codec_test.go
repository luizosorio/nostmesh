package nostr

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/protocol"
)

// Test identities, from the official NIP-44 vectors so the derived key is a
// known value rather than something this test invented.
const (
	aliceSecret = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268"
	bobPublic   = "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133"
)

func testNow() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

func testKey(t *testing.T) ConversationKey {
	t.Helper()

	key, err := DeriveConversationKey(aliceSecret, bobPublic)
	if err != nil {
		t.Fatalf("deriving conversation key: %v", err)
	}
	return key
}

func hexOf(seed byte, size int) string {
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return hex.EncodeToString(raw)
}

func b64Of(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func testEnvelope() protocol.Envelope {
	now := testNow()
	return protocol.Envelope{
		Version:   protocol.Version,
		Namespace: protocol.Namespace,
		Type:      protocol.TypeSessionRequest,
		MessageID: hexOf(1, 16),
		SessionID: hexOf(50, 32),
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Sender:    hexOf(100, 32),
		Recipient: hexOf(200, 32),
	}
}

func testPayload() protocol.Payload {
	return protocol.Payload{Request: &protocol.SessionRequest{
		Capabilities: protocol.Capabilities{
			ProtocolVersions: []int{protocol.Version},
			Transports:       []string{"wireguard/udp"},
		},
		TunnelKey: protocol.TunnelKey{
			PublicKey: b64Of(10),
			Nonce:     hexOf(20, 16),
			ExpiresAt: testNow().Add(5 * time.Minute).Unix(),
		},
	}}
}

func newCodec() *Codec {
	return NewCodec(func() time.Time { return testNow() })
}

// The derivation must match the official vector: agreement with other
// implementations is what makes the protocol interoperable, and testing only
// against ourselves would prove nothing.
func TestConversationKeyMatchesOfficialVector(t *testing.T) {
	const want = "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"

	key := testKey(t)
	if got := hex.EncodeToString(key[:]); got != want {
		t.Errorf("conversation key = %s, want the official vector %s", got, want)
	}
}

func TestSealAndOpenRoundTrip(t *testing.T) {
	codec := newCodec()
	key := testKey(t)

	sealed, err := codec.Seal(testEnvelope(), testPayload(), key)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if sealed.Body == "" {
		t.Fatal("sealing produced no body")
	}

	opened, err := codec.Open(sealed, key)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if opened.Request == nil {
		t.Fatal("round trip lost the request")
	}
	if opened.Request.TunnelKey.PublicKey != b64Of(10) {
		t.Error("round trip altered the tunnel key")
	}
}

// The body must not contain the payload in any readable form. A protocol that
// encrypts the wrong thing looks identical to one that encrypts correctly,
// until someone reads a relay's logs.
func TestSealedBodyRevealsNothing(t *testing.T) {
	codec := newCodec()

	sealed, err := codec.Seal(testEnvelope(), testPayload(), testKey(t))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	// Neither the ciphertext nor its decoded bytes may contain the plaintext.
	decoded, _ := base64.StdEncoding.DecodeString(sealed.Body)

	for _, secret := range []string{
		b64Of(10),       // the tunnel public key
		hexOf(20, 16),   // the nonce
		"wireguard/udp", // a capability
		"tunnel_key",    // a field name
		"protocol_versions",
	} {
		if strings.Contains(sealed.Body, secret) {
			t.Errorf("ciphertext contains %q", secret)
		}
		if strings.Contains(string(decoded), secret) {
			t.Errorf("decoded ciphertext contains %q", secret)
		}
	}
}

// Altering any authenticated envelope field after sealing must make the payload
// unopenable. This is what stops a relay from re-addressing a captured message.
func TestTamperedEnvelopeFailsToOpen(t *testing.T) {
	codec := newCodec()
	key := testKey(t)

	sealed, err := codec.Seal(testEnvelope(), testPayload(), key)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*protocol.Envelope)
	}{
		{"recipient", func(e *protocol.Envelope) { e.Recipient = hexOf(9, 32) }},
		{"sender", func(e *protocol.Envelope) { e.Sender = hexOf(9, 32) }},
		{"session id", func(e *protocol.Envelope) { e.SessionID = hexOf(9, 32) }},
		{"message id", func(e *protocol.Envelope) { e.MessageID = hexOf(9, 16) }},
		{"sequence", func(e *protocol.Envelope) { e.Seq = 99 }},
		{"type", func(e *protocol.Envelope) { e.Type = protocol.TypeSessionClose }},
		{"created", func(e *protocol.Envelope) { e.CreatedAt++ }},
		{"expires", func(e *protocol.Envelope) { e.ExpiresAt++ }},
		{"version", func(e *protocol.Envelope) { e.Version = 99 }},
		{"namespace", func(e *protocol.Envelope) { e.Namespace = "other" }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			tampered := sealed
			m.mutate(&tampered)

			if _, err := codec.Open(tampered, key); err == nil {
				t.Errorf("altering %s must make the payload unopenable", m.name)
			}
		})
	}
}

// A payload sealed for one recipient must not open with another pair's key.
func TestPayloadDoesNotOpenWithWrongKey(t *testing.T) {
	codec := newCodec()

	sealed, err := codec.Seal(testEnvelope(), testPayload(), testKey(t))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	var wrong ConversationKey
	for i := range wrong {
		wrong[i] = byte(i)
	}

	if _, err := codec.Open(sealed, wrong); !errors.Is(err, ErrDecryption) {
		t.Errorf("expected ErrDecryption, got: %v", err)
	}
}

// The decryption error must not distinguish a wrong key from a failed tag:
// either distinction is an oracle.
func TestDecryptionErrorRevealsNothing(t *testing.T) {
	codec := newCodec()
	key := testKey(t)

	sealed, err := codec.Seal(testEnvelope(), testPayload(), key)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	var wrongKey ConversationKey
	corrupted := sealed
	corrupted.Body = sealed.Body[:len(sealed.Body)-4] + "AAAA"

	_, wrongKeyErr := codec.Open(sealed, wrongKey)
	_, corruptedErr := codec.Open(corrupted, key)

	if wrongKeyErr == nil || corruptedErr == nil {
		t.Fatal("both cases must fail")
	}
	if wrongKeyErr.Error() != corruptedErr.Error() {
		t.Errorf("errors differ and leak which failed:\n  wrong key: %v\n  corrupted: %v",
			wrongKeyErr, corruptedErr)
	}
}

// The conversation key decrypts every message between two identities, so it is
// as sensitive as the identity key and must not be printable.
func TestConversationKeyNeverPrints(t *testing.T) {
	key := testKey(t)
	material := hex.EncodeToString(key[:8])

	for _, rendered := range []string{
		key.String(),
		strings.TrimSpace(strings.Join([]string{key.GoString()}, "")),
	} {
		if strings.Contains(rendered, material) {
			t.Errorf("conversation key material appeared in output: %s", rendered)
		}
		if !strings.Contains(rendered, "REDACTED") {
			t.Errorf("expected a redaction marker, got: %s", rendered)
		}
	}

	if _, err := json.Marshal(key); err == nil {
		t.Error("marshaling a conversation key must fail")
	}
}

// A payload whose type disagrees with the envelope must not seal: the type
// travels in both places precisely so a mismatch is detectable.
func TestSealRejectsTypeMismatch(t *testing.T) {
	codec := newCodec()

	envelope := testEnvelope()
	envelope.Type = protocol.TypeSessionClose

	if _, err := codec.Seal(envelope, testPayload(), testKey(t)); !errors.Is(err, protocol.ErrTypeMismatch) {
		t.Errorf("expected ErrTypeMismatch, got: %v", err)
	}
}

// An accept references an offer by hash, so any change to the terms must
// produce a different hash.
func TestOfferHashCoversEveryTerm(t *testing.T) {
	base := protocol.SessionOffer{
		Capabilities: protocol.Capabilities{
			ProtocolVersions: []int{protocol.Version},
			Transports:       []string{"wireguard/udp"},
		},
		TunnelKey: protocol.TunnelKey{
			PublicKey: b64Of(10),
			Nonce:     hexOf(20, 16),
			ExpiresAt: testNow().Add(time.Minute).Unix(),
		},
		AgreedVersion:    protocol.Version,
		AgreedTransports: []string{"wireguard/udp"},
	}

	baseline, err := OfferHash(base)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*protocol.SessionOffer)
	}{
		{"tunnel key", func(o *protocol.SessionOffer) { o.TunnelKey.PublicKey = b64Of(99) }},
		{"nonce", func(o *protocol.SessionOffer) { o.TunnelKey.Nonce = hexOf(99, 16) }},
		{"key expiry", func(o *protocol.SessionOffer) { o.TunnelKey.ExpiresAt++ }},
		{"agreed version", func(o *protocol.SessionOffer) { o.AgreedVersion = 99 }},
		{"transports", func(o *protocol.SessionOffer) { o.AgreedTransports = []string{"other"} }},
		{"overlay address", func(o *protocol.SessionOffer) { o.OverlayAddress = "10.0.0.1/32" }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := base
			m.mutate(&mutated)

			got, err := OfferHash(mutated)
			if err != nil {
				t.Fatalf("hashing: %v", err)
			}
			if got == baseline {
				t.Errorf("changing the %s did not change the offer hash", m.name)
			}
		})
	}
}

// Sealing the same payload twice must produce different ciphertext: NIP-44 uses
// a random nonce, and identical output would mean it was reused.
func TestSealIsNonDeterministic(t *testing.T) {
	codec := newCodec()
	key := testKey(t)

	first, err := codec.Seal(testEnvelope(), testPayload(), key)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	second, err := codec.Seal(testEnvelope(), testPayload(), key)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	if first.Body == second.Body {
		t.Error("identical ciphertext means the nonce was reused")
	}
}
