package protocol

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

// validRouteAnnounce is an announcement that passes, so each test alters one
// field and attributes the failure to it.
func validRouteAnnounce() RouteAnnounce {
	return RouteAnnounce{
		Routes:     []AnnouncedRoute{{Prefix: "10.20.30.0/24", Metric: 10}},
		NetworkID:  "lab",
		Version:    1,
		ValidUntil: testNow().Add(5 * time.Minute).Unix(),
	}
}

// A well-formed announcement is accepted, which is what makes the rejections
// below mean something.
func TestAValidRouteAnnouncementPasses(t *testing.T) {
	envelope := validEnvelope()
	envelope.Type = TypeRouteAnnounce
	announce := validRouteAnnounce()

	if err := ValidatePayload(Payload{RouteAnnounce: &announce}, envelope, testNow()); err != nil {
		t.Fatalf("a valid announcement was refused: %v", err)
	}
}

// A route message is validated rather than falling through untouched.
//
// The payload switch ends in a default that returns nil for the types carrying
// nothing to check. A new type that nobody added a case for lands there and is
// accepted whatever it holds, which is the failure this pins.
func TestRouteMessagesAreValidated(t *testing.T) {
	envelope := validEnvelope()
	envelope.Type = TypeRouteAnnounce

	empty := RouteAnnounce{}
	if err := ValidatePayload(Payload{RouteAnnounce: &empty}, envelope, testNow()); err == nil {
		t.Error("an empty announcement was accepted; the payload switch has no case for it")
	}

	envelope.Type = TypeRouteWithdraw
	emptyWithdraw := RouteWithdraw{}
	if err := ValidatePayload(Payload{RouteWithdraw: &emptyWithdraw}, envelope, testNow()); err == nil {
		t.Error("an empty withdrawal was accepted; the payload switch has no case for it")
	}
}

func TestRouteAnnouncementRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RouteAnnounce)
		want   error
	}{
		{"no routes", func(a *RouteAnnounce) { a.Routes = nil }, ErrMalformed},
		{"no network", func(a *RouteAnnounce) { a.NetworkID = "" }, ErrMalformed},
		{"no validity", func(a *RouteAnnounce) { a.ValidUntil = 0 }, ErrMalformed},
		{"negative validity", func(a *RouteAnnounce) { a.ValidUntil = -1 }, ErrMalformed},
		{
			"unparseable prefix",
			func(a *RouteAnnounce) { a.Routes[0].Prefix = "not-a-prefix" },
			ErrMalformed,
		},
		{
			"an address rather than a prefix",
			func(a *RouteAnnounce) { a.Routes[0].Prefix = "10.20.30.1" },
			ErrMalformed,
		},
		{
			// 10.20.30.1/24 and 10.20.30.0/24 are one destination. Accepting
			// both lets one sender hold two entries for it, which hides a
			// conflict and defeats duplicate suppression.
			"a prefix that is not canonical",
			func(a *RouteAnnounce) { a.Routes[0].Prefix = "10.20.30.1/24" },
			ErrMalformed,
		},
		{
			"the same prefix twice",
			func(a *RouteAnnounce) {
				a.Routes = append(a.Routes, AnnouncedRoute{Prefix: "10.20.30.0/24"})
			},
			ErrMalformed,
		},
		{
			"more routes than the limit",
			func(a *RouteAnnounce) {
				a.Routes = make([]AnnouncedRoute, maxAnnouncedRoutes+1)
				for i := range a.Routes {
					a.Routes[i] = AnnouncedRoute{Prefix: fmt.Sprintf("10.%d.0.0/16", i)}
				}
			},
			ErrTooLarge,
		},
	}

	envelope := validEnvelope()
	envelope.Type = TypeRouteAnnounce

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			announce := validRouteAnnounce()
			test.mutate(&announce)

			err := ValidatePayload(Payload{RouteAnnounce: &announce}, envelope, testNow())
			if !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRouteWithdrawalRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RouteWithdraw)
		want   error
	}{
		{"no prefixes", func(w *RouteWithdraw) { w.Prefixes = nil }, ErrMalformed},
		{"no network", func(w *RouteWithdraw) { w.NetworkID = "" }, ErrMalformed},
		{
			"unparseable prefix",
			func(w *RouteWithdraw) { w.Prefixes = []string{"not-a-prefix"} },
			ErrMalformed,
		},
		{
			"a prefix that is not canonical",
			func(w *RouteWithdraw) { w.Prefixes = []string{"10.20.30.1/24"} },
			ErrMalformed,
		},
		{
			"the same prefix twice",
			func(w *RouteWithdraw) { w.Prefixes = []string{"10.20.30.0/24", "10.20.30.0/24"} },
			ErrMalformed,
		},
	}

	envelope := validEnvelope()
	envelope.Type = TypeRouteWithdraw

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withdraw := RouteWithdraw{
				Prefixes:  []string{"10.20.30.0/24"},
				NetworkID: "lab",
				Version:   2,
			}
			test.mutate(&withdraw)

			err := ValidatePayload(Payload{RouteWithdraw: &withdraw}, envelope, testNow())
			if !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}
		})
	}
}

// A route type declared in the envelope must match the payload.
//
// The binding between the visible type and the encrypted content: a relay sees
// route.announce, and the receiver must not find a session message inside.
func TestARouteEnvelopeMustCarryARoutePayload(t *testing.T) {
	envelope := validEnvelope()
	envelope.Type = TypeRouteAnnounce

	withdraw := RouteWithdraw{Prefixes: []string{"10.0.0.0/8"}, NetworkID: "lab"}
	if err := ValidatePayload(Payload{RouteWithdraw: &withdraw}, envelope, testNow()); !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("error = %v, want %v", err, ErrTypeMismatch)
	}
}

// The new types are accepted by envelope validation.
//
// Without an entry in the closed set they are refused as unknown, which would
// make every route message fail before its payload is ever read.
func TestRouteTypesAreKnown(t *testing.T) {
	for _, kind := range []MessageType{TypeRouteAnnounce, TypeRouteWithdraw} {
		if !kind.IsKnown() {
			t.Errorf("%s is not in the closed set of known types", kind)
		}

		envelope := validEnvelope()
		envelope.Type = kind
		if err := ValidateEnvelope(envelope, localNodeKey(), testNow()); err != nil {
			t.Errorf("%s: envelope refused: %v", kind, err)
		}
	}
}
