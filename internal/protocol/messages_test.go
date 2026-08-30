package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func validCapabilities() Capabilities {
	return Capabilities{
		ProtocolVersions: []int{Version},
		Transports:       []string{"wireguard/udp"},
		CandidateTypes:   []string{"host", "srflx"},
	}
}

func validTunnelKey() TunnelKey {
	return TunnelKey{
		PublicKey: b64Of(10),
		Nonce:     hexOf(20, 16),
		ExpiresAt: testNow().Add(5 * time.Minute).Unix(),
	}
}

func validRequestPayload() Payload {
	return Payload{Request: &SessionRequest{
		Capabilities:   validCapabilities(),
		TunnelKey:      validTunnelKey(),
		OverlayAddress: "100.96.0.1/32",
	}}
}

func TestPayloadTypeDetection(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		want    MessageType
	}{
		{"request", validRequestPayload(), TypeSessionRequest},
		{"offer", Payload{Offer: &SessionOffer{}}, TypeSessionOffer},
		{"accept", Payload{Accept: &SessionAccept{}}, TypeSessionAccept},
		{"candidate", Payload{Candidate: &CandidateUpdate{}}, TypeCandidateUpdate},
		{"ready", Payload{Ready: &SessionReady{}}, TypeSessionReady},
		{"keepalive", Payload{Keepalive: &SessionKeepalive{}}, TypeSessionKeepalive},
		{"close", Payload{Close: &SessionClose{}}, TypeSessionClose},
		{"error", Payload{Error: &SessionError{}}, TypeSessionError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.payload.TypeOf()
			if err != nil {
				t.Fatalf("detecting type: %v", err)
			}
			if got != tt.want {
				t.Errorf("type = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestPayloadRejectsAmbiguity(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := (Payload{}).TypeOf(); !errors.Is(err, ErrEmptyPayload) {
			t.Errorf("expected ErrEmptyPayload, got: %v", err)
		}
	})

	t.Run("two messages", func(t *testing.T) {
		payload := Payload{Request: &SessionRequest{}, Close: &SessionClose{}}
		if _, err := payload.TypeOf(); !errors.Is(err, ErrMultiplePayloads) {
			t.Errorf("expected ErrMultiplePayloads, got: %v", err)
		}
	})
}

// The type appears in the clear so relays can route, and inside the encrypted
// payload so it is authenticated. A mismatch means one was tampered with.
func TestPayloadMustMatchEnvelopeType(t *testing.T) {
	envelope := validEnvelope()
	envelope.Type = TypeSessionClose

	err := ValidatePayload(validRequestPayload(), envelope, testNow())
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got: %v", err)
	}
}

// Substituting the WireGuard public key is the attack the binding exists to
// stop. These cases cover the ways a key could be malformed or stale; the
// binding to session and recipient is enforced by the envelope's associated
// data, tested separately.
func TestTunnelKeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TunnelKey)
		wantErr error
	}{
		{
			name:    "not base64",
			mutate:  func(k *TunnelKey) { k.PublicKey = "not base64!!" },
			wantErr: ErrMalformed,
		},
		{
			name:    "wrong length",
			mutate:  func(k *TunnelKey) { k.PublicKey = base64.StdEncoding.EncodeToString([]byte("short")) },
			wantErr: ErrMalformed,
		},
		{
			name: "all zeros",
			mutate: func(k *TunnelKey) {
				k.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			},
			wantErr: ErrMalformed,
		},
		{
			name:    "nonce not hex",
			mutate:  func(k *TunnelKey) { k.Nonce = "zzzz" },
			wantErr: ErrMalformed,
		},
		{
			name:    "nonce all zeros",
			mutate:  func(k *TunnelKey) { k.Nonce = strings.Repeat("00", 16) },
			wantErr: ErrMalformed,
		},
		{
			name:    "no expiry",
			mutate:  func(k *TunnelKey) { k.ExpiresAt = 0 },
			wantErr: ErrMalformed,
		},
		{
			name: "expired",
			mutate: func(k *TunnelKey) {
				k.ExpiresAt = testNow().Add(-time.Hour).Unix()
			},
			wantErr: ErrExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := validTunnelKey()
			tt.mutate(&key)

			payload := Payload{Request: &SessionRequest{
				Capabilities: validCapabilities(),
				TunnelKey:    key,
			}}

			err := ValidatePayload(payload, validEnvelope(), testNow())
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// A peer that speaks no version we implement must be refused rather than
// negotiated with, and one claiming agreement on a version we never offered is
// attempting a downgrade.
func TestVersionNegotiation(t *testing.T) {
	t.Run("peer speaks no shared version", func(t *testing.T) {
		payload := Payload{Request: &SessionRequest{
			Capabilities: Capabilities{
				ProtocolVersions: []int{Version + 1},
				Transports:       []string{"wireguard/udp"},
			},
			TunnelKey: validTunnelKey(),
		}}

		err := ValidatePayload(payload, validEnvelope(), testNow())
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("expected ErrUnsupportedVersion, got: %v", err)
		}
	})

	t.Run("offer agrees on a version we do not speak", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.Type = TypeSessionOffer

		payload := Payload{Offer: &SessionOffer{
			Capabilities:     validCapabilities(),
			TunnelKey:        validTunnelKey(),
			AgreedVersion:    Version + 1,
			AgreedTransports: []string{"wireguard/udp"},
		}}

		err := ValidatePayload(payload, envelope, testNow())
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("expected ErrUnsupportedVersion, got: %v", err)
		}
	})

	t.Run("offer agrees on no transport", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.Type = TypeSessionOffer

		payload := Payload{Offer: &SessionOffer{
			Capabilities:     validCapabilities(),
			TunnelKey:        validTunnelKey(),
			AgreedVersion:    Version,
			AgreedTransports: nil,
		}}

		if err := ValidatePayload(payload, envelope, testNow()); !errors.Is(err, ErrMalformed) {
			t.Errorf("expected ErrMalformed, got: %v", err)
		}
	})
}

// An accept references the offer by hash rather than restating its terms, so a
// modified offer cannot be accepted by replaying an earlier acceptance.
func TestAcceptRequiresValidOfferHash(t *testing.T) {
	envelope := validEnvelope()
	envelope.Type = TypeSessionAccept

	for _, hash := range []string{"", "abcd", strings.Repeat("zz", 32)} {
		t.Run(hash, func(t *testing.T) {
			payload := Payload{Accept: &SessionAccept{OfferHash: hash}}

			if err := ValidatePayload(payload, envelope, testNow()); !errors.Is(err, ErrMalformed) {
				t.Errorf("expected ErrMalformed, got: %v", err)
			}
		})
	}
}

func TestCandidateValidation(t *testing.T) {
	envelope := validEnvelope()
	envelope.Type = TypeCandidateUpdate

	validCandidate := Candidate{
		ID:        "c1",
		Type:      CandidateHost,
		Transport: "udp",
		Address:   "192.0.2.1:51820",
		Priority:  100,
		ExpiresAt: testNow().Add(time.Minute).Unix(),
	}

	t.Run("accepts a valid update", func(t *testing.T) {
		payload := Payload{Candidate: &CandidateUpdate{Added: []Candidate{validCandidate}}}
		if err := ValidatePayload(payload, envelope, testNow()); err != nil {
			t.Fatalf("expected the update to validate: %v", err)
		}
	})

	tests := []struct {
		name   string
		update CandidateUpdate
	}{
		{"empty update", CandidateUpdate{}},
		{"candidate without id", CandidateUpdate{Added: []Candidate{{Type: CandidateHost, Transport: "udp", Address: "1.2.3.4:1"}}}},
		{"unknown candidate type", CandidateUpdate{Added: []Candidate{{ID: "c1", Type: "magic", Transport: "udp", Address: "1.2.3.4:1"}}}},
		{"unknown transport", CandidateUpdate{Added: []Candidate{{ID: "c1", Type: CandidateHost, Transport: "sctp", Address: "1.2.3.4:1"}}}},
		{"address without port", CandidateUpdate{Added: []Candidate{{ID: "c1", Type: CandidateHost, Transport: "udp", Address: "1.2.3.4"}}}},
		{"too many candidates", CandidateUpdate{Added: make([]Candidate, 33)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := Payload{Candidate: &tt.update}
			if err := ValidatePayload(payload, envelope, testNow()); err == nil {
				t.Error("expected validation to fail")
			}
		})
	}

	t.Run("duplicate candidate id", func(t *testing.T) {
		second := validCandidate
		payload := Payload{Candidate: &CandidateUpdate{Added: []Candidate{validCandidate, second}}}

		if err := ValidatePayload(payload, envelope, testNow()); !errors.Is(err, ErrMalformed) {
			t.Errorf("expected ErrMalformed, got: %v", err)
		}
	})
}

// Close reasons and error codes are closed sets. An unknown value means the
// peer speaks a protocol this build does not.
func TestClosedEnumerations(t *testing.T) {
	t.Run("close reason", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.Type = TypeSessionClose

		valid := Payload{Close: &SessionClose{Reason: CloseNormal}}
		if err := ValidatePayload(valid, envelope, testNow()); err != nil {
			t.Errorf("a known reason must validate: %v", err)
		}

		invalid := Payload{Close: &SessionClose{Reason: "because"}}
		if err := ValidatePayload(invalid, envelope, testNow()); !errors.Is(err, ErrUnknownType) {
			t.Errorf("expected ErrUnknownType, got: %v", err)
		}
	})

	t.Run("error code", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.Type = TypeSessionError

		valid := Payload{Error: &SessionError{Code: ErrorUnauthorized}}
		if err := ValidatePayload(valid, envelope, testNow()); err != nil {
			t.Errorf("a known code must validate: %v", err)
		}

		invalid := Payload{Error: &SessionError{Code: "kaboom"}}
		if err := ValidatePayload(invalid, envelope, testNow()); !errors.Is(err, ErrUnknownType) {
			t.Errorf("expected ErrUnknownType, got: %v", err)
		}
	})
}

// Unknown fields are rejected so an attacker cannot smuggle data past the
// validator in a field the decoder would otherwise ignore.
func TestDecodeRejectsUnknownFields(t *testing.T) {
	envelope := validEnvelope()
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	withExtra := strings.Replace(string(raw), `{"v":`, `{"smuggled":"data","v":`, 1)

	if _, err := DecodeEnvelope([]byte(withExtra)); !errors.Is(err, ErrMalformed) {
		t.Errorf("expected ErrMalformed for an unknown field, got: %v", err)
	}
}

func TestDecodeRejectsOversized(t *testing.T) {
	oversized := make([]byte, MaxEnvelopeSize+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	if _, err := DecodeEnvelope(oversized); !errors.Is(err, ErrTooLarge) {
		t.Errorf("expected ErrTooLarge, got: %v", err)
	}
}

// Deeply nested JSON is rejected before parsing: it is going to fail anyway,
// and bounding it early keeps the cost proportional to the refusal.
func TestDecodeRejectsDeepNesting(t *testing.T) {
	deep := strings.Repeat("[", MaxJSONDepth+5) + strings.Repeat("]", MaxJSONDepth+5)

	if _, err := DecodeEnvelope([]byte(deep)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("expected ErrTooLarge, got: %v", err)
	}
}

// Braces inside a string are data, not structure, and must not count toward the
// nesting limit.
func TestDepthCheckIgnoresBracesInStrings(t *testing.T) {
	envelope := validEnvelope()
	envelope.Body = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("{", 100)))

	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	if _, err := DecodeEnvelope(raw); err != nil {
		t.Errorf("braces inside a string must not count as nesting: %v", err)
	}
}
