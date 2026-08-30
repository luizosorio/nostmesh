package protocol

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// FuzzDecodeEnvelope feeds arbitrary bytes to the envelope decoder.
//
// The decoder is the first thing a hostile relay reaches, so it must fail
// rather than panic on anything. A panic in a daemon is a denial of service
// that any peer can trigger.
func FuzzDecodeEnvelope(f *testing.F) {
	// Seeds: valid input, plausible corruptions, and shapes known to break
	// naive parsers.
	valid, err := json.Marshal(validEnvelope())
	if err != nil {
		f.Fatalf("encoding seed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"v":"one"}`))
	f.Add([]byte(`{"v":1,"namespace":"` + Namespace + `"}`))
	f.Add([]byte("\x00\x01\x02"))
	f.Add([]byte(`{"body":"` + string(make([]byte, 1000)) + `"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		envelope, err := DecodeEnvelope(data)
		if err != nil {
			return
		}

		// Anything that decoded must survive validation without panicking,
		// whatever verdict it reaches.
		_ = ValidateEnvelope(envelope, hexOf(200, 32), testNow())

		// Associated data is computed over attacker-controlled fields, so it
		// must not panic on any of them either.
		_ = envelope.AssociatedData()
	})
}

// FuzzDecodePayload feeds arbitrary bytes to the payload decoder.
//
// A payload reaches this point only after decryption, so an attacker needs the
// conversation key to drive it directly. It is fuzzed anyway: an authorized but
// malicious peer is exactly the threat the protocol assumes.
func FuzzDecodePayload(f *testing.F) {
	valid, err := json.Marshal(Payload{Request: &SessionRequest{
		Capabilities: Capabilities{
			ProtocolVersions: []int{Version},
			Transports:       []string{"wireguard/udp"},
		},
		TunnelKey: TunnelKey{
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			Nonce:     hexOf(20, 16),
			ExpiresAt: testNow().Add(time.Minute).Unix(),
		},
	}})
	if err != nil {
		f.Fatalf("encoding seed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"request":{}}`))
	f.Add([]byte(`{"request":{},"close":{}}`))
	f.Add([]byte(`{"candidate":{"added":[]}}`))
	f.Add([]byte(`{"request":{"tunnel_key":{"public_key":""}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := DecodePayload(data)
		if err != nil {
			return
		}

		_, _ = payload.TypeOf()
		_ = ValidatePayload(payload, validEnvelope(), testNow())
	})
}

// FuzzValidateEnvelope drives validation with structured but arbitrary field
// values, reaching paths the decoder would reject before validation sees them.
func FuzzValidateEnvelope(f *testing.F) {
	f.Add(1, "ns", "type", "msg", "session", uint64(0), int64(0), int64(0), "from", "to", "body")

	f.Fuzz(func(t *testing.T,
		version int, namespace, msgType, messageID, sessionID string,
		seq uint64, created, expires int64, sender, recipient, body string,
	) {
		envelope := Envelope{
			Version:   version,
			Namespace: namespace,
			Type:      MessageType(msgType),
			MessageID: messageID,
			SessionID: sessionID,
			Seq:       seq,
			CreatedAt: created,
			ExpiresAt: expires,
			Sender:    sender,
			Recipient: recipient,
			Body:      body,
		}

		_ = ValidateEnvelope(envelope, hexOf(200, 32), testNow())
		_ = envelope.AssociatedData()
		_ = envelope.CreatedTime()
		_ = envelope.ExpiryTime()
	})
}

// FuzzCheckDepth targets the nesting check directly, since it parses bytes by
// hand and is therefore the most likely place for an indexing mistake.
func FuzzCheckDepth(f *testing.F) {
	f.Add([]byte(`{"a":{"b":[1,2,3]}}`))
	f.Add([]byte(`{"a":"}}}}}}"}`))
	f.Add([]byte(`{"a":"\\"}`))
	f.Add([]byte(`[[[[[[[[[[`))
	f.Add([]byte(`"unterminated`))
	f.Add([]byte(`{"a":"\`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = checkDepth(data)
	})
}
