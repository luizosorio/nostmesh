package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// goldenCase is one vector: an envelope, whether it should validate, and why.
type goldenCase struct {
	Name string `json:"name"`

	// Envelope is the message under test.
	Envelope Envelope `json:"envelope"`

	// Valid says whether validation should succeed.
	Valid bool `json:"valid"`

	// Reason explains the expectation, for a reader of the file.
	Reason string `json:"reason"`

	// LocalNode is the recipient key validation runs against.
	LocalNode string `json:"local_node"`

	// NowUnix is the clock reading validation uses, so the vectors do not
	// expire and do not depend on when the tests run.
	NowUnix int64 `json:"now_unix"`
}

const goldenFile = "testdata/envelopes.json"

// buildGoldenCases produces the vector set.
//
// They are generated rather than written by hand so the valid cases cannot
// drift out of sync with the types, and regenerating after a deliberate format
// change is a visible diff.
func buildGoldenCases() []goldenCase {
	now := testNow()
	local := hexOf(200, 32)

	valid := func(name, reason string, mutate func(*Envelope)) goldenCase {
		e := validEnvelope()
		if mutate != nil {
			mutate(&e)
		}
		return goldenCase{
			Name: name, Envelope: e, Valid: true,
			Reason: reason, LocalNode: local, NowUnix: now.Unix(),
		}
	}
	invalid := func(name, reason string, mutate func(*Envelope)) goldenCase {
		e := validEnvelope()
		mutate(&e)
		return goldenCase{
			Name: name, Envelope: e, Valid: false,
			Reason: reason, LocalNode: local, NowUnix: now.Unix(),
		}
	}

	return []goldenCase{
		valid("minimal_request", "a well-formed session request", nil),
		valid("with_reply_to", "a message referencing a prior one", func(e *Envelope) {
			e.Type = TypeSessionOffer
			e.ReplyTo = hexOf(1, 16)
			e.Seq = 0
		}),
		valid("later_sequence", "ordering comes from seq, not timestamps", func(e *Envelope) {
			e.Type = TypeCandidateUpdate
			e.Seq = 7
		}),
		valid("at_expiry_boundary", "valid up to but not including expiry", func(e *Envelope) {
			e.ExpiresAt = testNow().Add(time.Second).Unix()
		}),

		invalid("future_version", "a version this build does not implement", func(e *Envelope) {
			e.Version = Version + 1
		}),
		invalid("foreign_namespace", "another protocol's messages must not be parsed", func(e *Envelope) {
			e.Namespace = "com.example.other"
		}),
		invalid("unknown_type", "a type outside the closed set", func(e *Envelope) {
			e.Type = "session.invented"
		}),
		invalid("critical_extension", "an extension the sender called essential", func(e *Envelope) {
			e.Critical = []string{"future.feature"}
		}),
		invalid("zero_session_id", "an all-zero identifier means uninitialized memory", func(e *Envelope) {
			e.SessionID = strings.Repeat("00", 32)
		}),
		invalid("self_addressed", "sender and recipient must differ", func(e *Envelope) {
			e.Sender = e.Recipient
		}),
		invalid("empty_body", "an envelope with no payload", func(e *Envelope) {
			e.Body = ""
		}),
		invalid("expired", "outside the validity window beyond tolerated skew", func(e *Envelope) {
			e.CreatedAt = testNow().Add(-time.Hour).Unix()
			e.ExpiresAt = testNow().Add(-time.Hour + time.Minute).Unix()
		}),
		invalid("not_yet_valid", "claimed to start further ahead than skew allows", func(e *Envelope) {
			e.CreatedAt = testNow().Add(time.Hour).Unix()
			e.ExpiresAt = testNow().Add(time.Hour + time.Minute).Unix()
		}),
		invalid("window_too_long", "a validity window beyond the protocol limit", func(e *Envelope) {
			e.ExpiresAt = e.CreatedAt + int64((MaxValidity + time.Hour).Seconds())
		}),
		invalid("expiry_before_creation", "a window that closes before it opens", func(e *Envelope) {
			e.ExpiresAt = e.CreatedAt - 1
		}),
		invalid("wrong_recipient", "addressed to another node", func(e *Envelope) {
			e.Recipient = hexOf(77, 32)
		}),
	}
}

// TestGoldenVectorsMatchStoredFile checks the committed vectors against what
// the current code produces.
//
// A difference means the wire format changed. That is sometimes intended — then
// regenerate with -update and review the diff — and sometimes an accident,
// which is exactly what this catches.
func TestGoldenVectorsMatchStoredFile(t *testing.T) {
	generated := buildGoldenCases()

	encoded, err := json.MarshalIndent(generated, "", "  ")
	if err != nil {
		t.Fatalf("encoding vectors: %v", err)
	}
	encoded = append(encoded, '\n')

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(goldenFile), 0o755); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(goldenFile, encoded, 0o644); err != nil {
			t.Fatalf("writing vectors: %v", err)
		}
		t.Log("golden vectors regenerated")
		return
	}

	stored, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("reading %s: %v; regenerate with UPDATE_GOLDEN=1", goldenFile, err)
	}

	if string(stored) != string(encoded) {
		t.Errorf("the wire format changed.\nIf intended, regenerate with UPDATE_GOLDEN=1 go test ./internal/protocol/ and review the diff.")
	}
}

// TestGoldenVectorsValidateAsExpected runs the stored vectors through
// validation. This is the interoperability check: a peer with these bytes must
// reach the same verdict.
func TestGoldenVectorsValidateAsExpected(t *testing.T) {
	stored, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("reading %s: %v", goldenFile, err)
	}

	var cases []goldenCase
	if err := json.Unmarshal(stored, &cases); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("the vector file is empty")
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			err := ValidateEnvelope(tc.Envelope, tc.LocalNode, time.Unix(tc.NowUnix, 0).UTC())

			if tc.Valid && err != nil {
				t.Errorf("%s should validate (%s), got: %v", tc.Name, tc.Reason, err)
			}
			if !tc.Valid && err == nil {
				t.Errorf("%s should be rejected (%s), but validated", tc.Name, tc.Reason)
			}
		})
	}
}

// The vectors must carry nothing that looks like a real secret, since they are
// committed and read by anyone.
func TestGoldenVectorsCarryNoSecrets(t *testing.T) {
	stored, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("reading %s: %v", goldenFile, err)
	}

	content := string(stored)
	for _, forbidden := range []string{"private", "secret", "nsec", "privkey"} {
		if strings.Contains(strings.ToLower(content), forbidden) {
			t.Errorf("the vector file mentions %q", forbidden)
		}
	}
}

// Both valid and invalid cases must be present: a suite of only-valid vectors
// proves the parser accepts good input but says nothing about whether it
// rejects bad input, which is the half that matters for security.
func TestGoldenVectorsCoverBothOutcomes(t *testing.T) {
	cases := buildGoldenCases()

	var valid, invalid int
	for _, tc := range cases {
		if tc.Valid {
			valid++
		} else {
			invalid++
		}
	}

	if valid == 0 {
		t.Error("no valid vectors")
	}
	if invalid == 0 {
		t.Error("no invalid vectors")
	}
	if invalid < valid {
		t.Errorf("only %d invalid vectors against %d valid; rejection deserves at least equal coverage",
			invalid, valid)
	}
}
