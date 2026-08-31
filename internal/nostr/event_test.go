package nostr

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T, seed byte) *Signer {
	t.Helper()

	signer, err := NewSigner(testPrivateKey(t, seed))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}
	return signer
}

// The id must be the digest of the canonical NIP-01 serialization. This pins
// the exact bytes: a change in field order, spacing or encoding produces an id
// no relay and no other implementation agrees with, and the failure would show
// up only against a real relay.
func TestEventIDMatchesCanonicalSerialization(t *testing.T) {
	signer := testSigner(t, 1)
	createdAt := time.Unix(1700000000, 0)
	tags := [][]string{{"p", "abc"}}

	event, _, err := BuildEvent(signer, 31111, tags, "hello", createdAt)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	// Recomputed independently of the production helper, so a bug in the
	// helper cannot make this test agree with it.
	expected := `[0,"` + signer.PublicKey().String() + `",1700000000,31111,[["p","abc"]],"hello"]`

	serialized, err := serializeForID(signer.PublicKey().String(), 1700000000, 31111, tags, "hello")
	if err != nil {
		t.Fatalf("serializing: %v", err)
	}
	if string(serialized) != expected {
		t.Fatalf("serialization is not canonical:\n got %s\nwant %s", serialized, expected)
	}

	if err := VerifyEvent(event); err != nil {
		t.Fatalf("a freshly built event must verify: %v", err)
	}
}

// Nil tags must serialize as [] and not null, or the id disagrees with every
// other implementation.
func TestEmptyTagsSerializeAsArray(t *testing.T) {
	serialized, err := serializeForID("aa", 1, 31111, nil, "")
	if err != nil {
		t.Fatalf("serializing: %v", err)
	}
	if strings.Contains(string(serialized), "null") {
		t.Errorf("nil tags must encode as [], got %s", serialized)
	}
}

// Changing any covered field must invalidate the event. Each case rewrites one
// field around an otherwise valid signature, which is exactly what a malicious
// relay would attempt.
func TestVerifyRejectsTamperedFields(t *testing.T) {
	signer := testSigner(t, 2)
	event, _, err := BuildEvent(signer, 31111, [][]string{{"p", "abc"}}, "original", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	cases := map[string]func(*Event){
		"content":    func(e *Event) { e.Content = "rewritten" },
		"kind":       func(e *Event) { e.Kind = 1 },
		"created_at": func(e *Event) { e.CreatedAt++ },
		"tags":       func(e *Event) { e.Tags = [][]string{{"p", "other"}} },
	}

	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := event
			tamper(&tampered)

			err := VerifyEvent(tampered)
			if !errors.Is(err, ErrEventIDMismatch) {
				t.Errorf("tampering with %s must be caught, got %v", name, err)
			}
		})
	}
}

// An event whose id is recomputed after tampering still must not verify: the
// signature covers the digest, so repairing the id does not repair the event.
// This is the case that a signature-only or an id-only check would miss.
func TestVerifyRejectsResignedIDWithForeignSignature(t *testing.T) {
	signer := testSigner(t, 3)
	event, _, err := BuildEvent(signer, 31111, nil, "original", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	// Rewrite the content and recompute the id so it matches, leaving the
	// original signature in place.
	forged, _, err := BuildEvent(testSigner(t, 4), 31111, nil, "rewritten", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building forged: %v", err)
	}
	forged.PublicKey = event.PublicKey
	forged.Signature = event.Signature

	if err := VerifyEvent(forged); err == nil {
		t.Error("an event with a foreign signature must not verify")
	}
}

// A signature from a different key must not verify, even with a correct id.
func TestVerifyRejectsWrongSigner(t *testing.T) {
	event, _, err := BuildEvent(testSigner(t, 5), 31111, nil, "body", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	other, _, err := BuildEvent(testSigner(t, 6), 31111, nil, "body", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building other: %v", err)
	}

	event.Signature = other.Signature
	if err := VerifyEvent(event); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected signature rejection, got %v", err)
	}
}

// The raw bytes must round-trip: what is published is what is verified.
func TestBuildEventRoundTrips(t *testing.T) {
	signer := testSigner(t, 7)
	event, raw, err := BuildEvent(signer, 31111, [][]string{{"p", "abc"}}, "payload", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	parsed, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if parsed.ID != event.ID || parsed.Signature != event.Signature {
		t.Error("round trip changed the event")
	}
	if err := VerifyEvent(parsed); err != nil {
		t.Errorf("round-tripped event must verify: %v", err)
	}
}

// The relay reads the id from the published bytes, so the encoded form must
// carry it under the name NIP-01 specifies.
func TestRawEventCarriesRelayFields(t *testing.T) {
	_, raw, err := BuildEvent(testSigner(t, 8), 31111, nil, "x", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	for _, field := range []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("published event is missing %q", field)
		}
	}
}

func TestParseRejectsIncompleteEvent(t *testing.T) {
	cases := map[string]string{
		"not json":     `{`,
		"no id":        `{"pubkey":"aa","sig":"bb"}`,
		"no pubkey":    `{"id":"aa","sig":"bb"}`,
		"no signature": `{"id":"aa","pubkey":"bb"}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEvent([]byte(raw)); !errors.Is(err, ErrEventMalformed) {
				t.Errorf("expected malformed, got %v", err)
			}
		})
	}
}

// The d tag decides what a relay replaces. Two different messages in one
// session must never collide, or the later one silently deletes the earlier.
func TestReplaceableTagSeparatesMessages(t *testing.T) {
	session := "session-a"

	request := ReplaceableTag(session, "session.request", 1)
	offer := ReplaceableTag(session, "session.offer", 2)
	firstCandidate := ReplaceableTag(session, "candidate.update", 3)
	secondCandidate := ReplaceableTag(session, "candidate.update", 4)

	if request[0] != "d" {
		t.Errorf("tag must be named d, got %q", request[0])
	}

	seen := map[string]string{}
	for name, tag := range map[string][]string{
		"request":          request,
		"offer":            offer,
		"first candidate":  firstCandidate,
		"second candidate": secondCandidate,
	} {
		if previous, collides := seen[tag[1]]; collides {
			t.Errorf("%s and %s share d value %q; one would replace the other", name, previous, tag[1])
		}
		seen[tag[1]] = name
	}

	// A retransmission of the same message must reuse the value, so it
	// supersedes its own earlier attempt rather than accumulating.
	if got := ReplaceableTag(session, "session.request", 1); got[1] != request[1] {
		t.Errorf("a retransmission must reuse the d value: %q != %q", got[1], request[1])
	}

	// A different session must never collide with this one.
	if got := ReplaceableTag("session-b", "session.request", 1); got[1] == request[1] {
		t.Error("different sessions must not share a d value")
	}
}

func TestRecipientTag(t *testing.T) {
	signer := testSigner(t, 9)
	tag := RecipientTag(signer.PublicKey())

	if tag[0] != "p" {
		t.Errorf("recipient tag must be named p, got %q", tag[0])
	}
	if tag[1] != signer.PublicKey().String() {
		t.Error("recipient tag must carry the recipient key")
	}
}
