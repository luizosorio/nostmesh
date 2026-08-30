package protocol

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func testNow() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

// hexOf builds a hex identifier of the given byte length from a seed.
func hexOf(seed byte, size int) string {
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return hex.EncodeToString(raw)
}

// b64Of builds a base64 key from a seed.
func b64Of(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func validEnvelope() Envelope {
	now := testNow()
	return Envelope{
		Version:   Version,
		Namespace: Namespace,
		Type:      TypeSessionRequest,
		MessageID: hexOf(1, 16),
		SessionID: hexOf(50, 32),
		Seq:       0,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Sender:    hexOf(100, 32),
		Recipient: hexOf(200, 32),
		Body:      base64.StdEncoding.EncodeToString([]byte("encrypted")),
	}
}

func localNodeKey() string { return hexOf(200, 32) }

func TestValidateEnvelopeAcceptsValid(t *testing.T) {
	if err := ValidateEnvelope(validEnvelope(), localNodeKey(), testNow()); err != nil {
		t.Fatalf("expected a valid envelope, got: %v", err)
	}
}

// Each case is a way a hostile or broken peer could shape a message. Rejecting
// them cheaply, before any decryption, is what keeps garbage from costing CPU.
func TestValidateEnvelopeRejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Envelope)
		wantErr error
	}{
		{
			name:    "future protocol version",
			mutate:  func(e *Envelope) { e.Version = Version + 1 },
			wantErr: ErrUnsupportedVersion,
		},
		{
			name:    "past protocol version",
			mutate:  func(e *Envelope) { e.Version = 0 },
			wantErr: ErrUnsupportedVersion,
		},
		{
			name:    "another protocol's namespace",
			mutate:  func(e *Envelope) { e.Namespace = "com.example.other" },
			wantErr: ErrUnknownNamespace,
		},
		{
			name:    "unknown message type",
			mutate:  func(e *Envelope) { e.Type = "session.invented" },
			wantErr: ErrUnknownType,
		},
		{
			name:    "unsupported critical extension",
			mutate:  func(e *Envelope) { e.Critical = []string{"future.feature"} },
			wantErr: ErrCriticalExtension,
		},
		{
			name:    "too many critical extensions",
			mutate:  func(e *Envelope) { e.Critical = make([]string, MaxCriticalExtensions+1) },
			wantErr: ErrTooLarge,
		},
		{
			name:    "message id not hex",
			mutate:  func(e *Envelope) { e.MessageID = "not-hex-at-all!!" },
			wantErr: ErrMalformed,
		},
		{
			name:    "message id wrong length",
			mutate:  func(e *Envelope) { e.MessageID = hexOf(1, 8) },
			wantErr: ErrMalformed,
		},
		{
			name:    "all-zero session id",
			mutate:  func(e *Envelope) { e.SessionID = strings.Repeat("00", 32) },
			wantErr: ErrMalformed,
		},
		{
			name:    "sender equals recipient",
			mutate:  func(e *Envelope) { e.Sender = e.Recipient },
			wantErr: ErrMalformed,
		},
		{
			name:    "empty body",
			mutate:  func(e *Envelope) { e.Body = "" },
			wantErr: ErrMalformed,
		},
		{
			name:    "body not base64",
			mutate:  func(e *Envelope) { e.Body = "not base64!!!" },
			wantErr: ErrMalformed,
		},
		{
			name:    "oversized body",
			mutate:  func(e *Envelope) { e.Body = strings.Repeat("A", MaxPayloadSize+1) },
			wantErr: ErrTooLarge,
		},
		{
			name:    "expiry before creation",
			mutate:  func(e *Envelope) { e.ExpiresAt = e.CreatedAt - 1 },
			wantErr: ErrMalformed,
		},
		{
			name:    "validity window too long",
			mutate:  func(e *Envelope) { e.ExpiresAt = e.CreatedAt + int64((MaxValidity + time.Hour).Seconds()) },
			wantErr: ErrMalformed,
		},
		{
			name: "expired beyond tolerated skew",
			mutate: func(e *Envelope) {
				e.CreatedAt = testNow().Add(-time.Hour).Unix()
				e.ExpiresAt = testNow().Add(-time.Hour + time.Minute).Unix()
			},
			wantErr: ErrExpired,
		},
		{
			name: "created too far in the future",
			mutate: func(e *Envelope) {
				e.CreatedAt = testNow().Add(time.Hour).Unix()
				e.ExpiresAt = testNow().Add(time.Hour + time.Minute).Unix()
			},
			wantErr: ErrNotYetValid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := validEnvelope()
			tt.mutate(&envelope)

			err := ValidateEnvelope(envelope, localNodeKey(), testNow())
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

// A message addressed to another node must be refused even if it is otherwise
// perfectly formed: relays deliver by tag, and a tag can name anyone.
func TestValidateEnvelopeRejectsWrongRecipient(t *testing.T) {
	envelope := validEnvelope()

	err := ValidateEnvelope(envelope, hexOf(77, 32), testNow())
	if !errors.Is(err, ErrWrongRecipient) {
		t.Fatalf("expected ErrWrongRecipient, got: %v", err)
	}
}

// Clock skew within tolerance must be accepted; the two hosts are not
// synchronized and never will be.
func TestValidateEnvelopeToleratesClockSkew(t *testing.T) {
	for _, skew := range []time.Duration{-MaxClockSkew + time.Second, 0, MaxClockSkew - time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			envelope := validEnvelope()

			if err := ValidateEnvelope(envelope, localNodeKey(), testNow().Add(skew)); err != nil {
				t.Errorf("skew of %s must be tolerated, got: %v", skew, err)
			}
		})
	}
}

// The associated data binds the envelope's cleartext fields to the encrypted
// payload. Changing any of them must change the bytes, or an attacker could
// re-address a captured payload.
func TestAssociatedDataBindsEveryField(t *testing.T) {
	base := validEnvelope()
	baseline := string(base.AssociatedData())

	mutations := []struct {
		name   string
		mutate func(*Envelope)
	}{
		{"version", func(e *Envelope) { e.Version = 99 }},
		{"namespace", func(e *Envelope) { e.Namespace = "other" }},
		{"type", func(e *Envelope) { e.Type = TypeSessionClose }},
		{"message id", func(e *Envelope) { e.MessageID = hexOf(9, 16) }},
		{"session id", func(e *Envelope) { e.SessionID = hexOf(9, 32) }},
		{"sequence", func(e *Envelope) { e.Seq = 42 }},
		{"created", func(e *Envelope) { e.CreatedAt++ }},
		{"expires", func(e *Envelope) { e.ExpiresAt++ }},
		{"sender", func(e *Envelope) { e.Sender = hexOf(9, 32) }},
		{"recipient", func(e *Envelope) { e.Recipient = hexOf(9, 32) }},
		{"critical", func(e *Envelope) { e.Critical = []string{"x"} }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := validEnvelope()
			m.mutate(&mutated)

			if string(mutated.AssociatedData()) == baseline {
				t.Errorf("changing %s did not change the associated data", m.name)
			}
		})
	}
}

// Length-prefixed encoding must make field boundaries unambiguous: two
// different field sets cannot produce identical bytes.
func TestAssociatedDataIsUnambiguous(t *testing.T) {
	first := validEnvelope()
	first.Namespace = "ab"
	first.MessageID = hexOf(1, 16)

	second := validEnvelope()
	second.Namespace = "a"
	second.MessageID = hexOf(1, 16)

	if string(first.AssociatedData()) == string(second.AssociatedData()) {
		t.Error("different field values produced identical associated data")
	}
}
