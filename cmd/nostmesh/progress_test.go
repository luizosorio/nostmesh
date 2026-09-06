package main

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/nostr"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// progressOutput runs a function against a progress logger and returns what a
// person would have seen.
func progressOutput(t *testing.T, emit func(*slog.Logger)) string {
	t.Helper()

	var buffer bytes.Buffer

	// Through the function the command calls, not through a handler this test
	// builds. Asserting on its own handler would prove the handler works and say
	// nothing about whether `nostmesh session` wires it up.
	emit(sessionProgressLogger(&output{w: &buffer}))

	return buffer.String()
}

// Somebody running `nostmesh session` sees progress as prose, not as JSON.
//
// This is the property the structured logger must not cost. The CLI's output is
// what a person reads while waiting for a session that spans two hosts and
// several layers, where every failure looks identical from outside — a wait that
// ends empty.
func TestTheSessionCommandPrintsProgressAsProse(t *testing.T) {
	rendered := progressOutput(t, func(log *slog.Logger) {
		log.Info("connected", observability.Event("relay.connected"), slog.String("relay", "relay.example"))
		log.Debug("received", observability.Event("envelope.decrypted"),
			slog.String("type", "session.offer"), slog.String("seq", "1"))
		log.Info("promoted", observability.Event("candidate.promoted"))
	})

	for _, want := range []string{
		"connected to relay.example",
		"received session.offer seq=1",
		"path verified",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the progress output is missing %q:\n%s", want, rendered)
		}
	}

	// The shape matters as much as the content: these lines are indented under
	// the "connecting to ..." the command prints first.
	for _, line := range strings.Split(strings.TrimRight(rendered, "\n"), "\n") {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("a progress line lost its indentation: %q", line)
		}
	}
}

// JSON must never reach the terminal.
//
// The daemon's handler and this one render the same records; wiring the wrong
// one into the CLI would fill a person's terminal with structured output, which
// is the regression this guards.
func TestTheSessionCommandNeverPrintsJSON(t *testing.T) {
	rendered := progressOutput(t, func(log *slog.Logger) {
		log.Info("connected", observability.Event("relay.connected"), slog.String("relay", "relay.example"))
	})

	for _, marker := range []string{`{"`, `"level":`, `"event":`, `"time":`} {
		if strings.Contains(rendered, marker) {
			t.Errorf("structured output reached the terminal (%q):\n%s", marker, rendered)
		}
	}
}

// An event with no phrasing is dropped rather than printed raw.
//
// The vocabulary is partial on purpose: a session coming up cleanly should print
// a handful of lines, not a transcript. Printing an unrecognised record raw
// would turn every event added later into terminal noise nobody chose.
func TestAnUnphrasedEventIsNotPrinted(t *testing.T) {
	rendered := progressOutput(t, func(log *slog.Logger) {
		log.Debug("internal bookkeeping", observability.Event("journal.transaction.planned"))
	})

	if rendered != "" {
		t.Errorf("an event with no phrasing was printed anyway: %q", rendered)
	}
}

// A reason is rendered as words, not as a code.
//
// reason_code is written for a query; a person reading a terminal wants the
// sentence. Both come from the same record.
func TestAReasonIsRenderedForAPerson(t *testing.T) {
	rendered := progressOutput(t, func(log *slog.Logger) {
		log.Warn("ignored", observability.Event("envelope.rejected"),
			observability.Reason(observability.ReasonBadSignature))
	})

	if !strings.Contains(rendered, "bad signature") {
		t.Errorf("the reason was not rendered for a person to read: %q", rendered)
	}
	if strings.Contains(rendered, "bad_signature") {
		t.Errorf("the raw code reached the terminal: %q", rendered)
	}
}

// Attributes fixed by a child logger reach the phrasing.
func TestAttributesFromAChildLoggerAreRendered(t *testing.T) {
	rendered := progressOutput(t, func(log *slog.Logger) {
		observability.Component(log, observability.ComponentNostr).
			Info("connected", observability.Event("relay.connected"), slog.String("relay", "relay.example"))
	})

	if !strings.Contains(rendered, "connected to relay.example") {
		t.Errorf("a record from a component logger was not rendered: %q", rendered)
	}
}

// The level filters what a person sees.
func TestProgressRespectsTheLevel(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(newProgressHandler(&output{w: &buffer}, slog.LevelInfo))

	logger.Debug("received", observability.Event("envelope.decrypted"),
		slog.String("type", "session.offer"), slog.String("seq", "1"))

	if buffer.Len() != 0 {
		t.Errorf("a debug record reached the terminal at info level: %q", buffer.String())
	}
}

// A refusal reports a code, never the error a peer's message produced.
//
// The protocol specification forbids logging rejected content in full, and the
// error text of a refusal is derived from what the peer sent. This is the guard
// on the replacement for the fmt.Sprintf that used to interpolate it.
func TestARefusalNeverCarriesThePeersErrorText(t *testing.T) {
	// A refusal error shaped the way a hostile peer could arrange, carrying a
	// marker that must not survive into the record.
	hostile := errors.New("MARKER-attacker-controlled-text")

	if code := classifyRejection(hostile); strings.Contains(code, "MARKER") {
		t.Errorf("the peer's error text reached the reason code: %q", code)
	}
}

// Classification uses the sentinel errors rather than message text.
//
// Matching on text would stop classifying the first time a message was reworded,
// and the failure is silent: a log that says "malformed" about a refusal whose
// real reason it knows.
func TestRejectionsAreClassifiedBySentinel(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want string
	}{
		{"expired", fmt.Errorf("wrapped: %w", protocol.ErrExpired), observability.ReasonExpired},
		{"too large", fmt.Errorf("wrapped: %w", protocol.ErrTooLarge), observability.ReasonOversized},
		{"wrong recipient", protocol.ErrWrongRecipient, observability.ReasonWrongRecipient},
		{"bad signature", nostr.ErrInvalidSignature, observability.ReasonBadSignature},
		{"another peer", errNotFromPeer, observability.ReasonWrongRecipient},
		{"another session", fmt.Errorf("%w: x", errWrongSession), observability.ReasonUnknownSession},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := classifyRejection(testCase.err); got != testCase.want {
				t.Errorf("classifyRejection = %q, want %q", got, testCase.want)
			}
		})
	}
}
