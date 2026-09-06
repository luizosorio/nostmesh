package orchestrator

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// A failure is classified by sentinel, never by message text.
//
// Matching on text would stop classifying the first time an error was reworded,
// and the failure is silent: a log reporting "internal" about a cause it knows.
func TestDriverFailuresAreClassifiedBySentinel(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want string
	}{
		{"unauthorized", ErrUnauthorized, observability.ReasonUnauthorized},
		{"wrapped unauthorized", errors.New("x"), observability.ReasonInternal},
		{"no request", ErrNoRequest, observability.ReasonTimeout},
		{"session dropped", ErrSessionDropped, observability.ReasonHandshakeStale},
		{"roaming rejected", ErrRoamingRejected, observability.ReasonRoamRejected},
		{"no path", connectivity.ErrNoValidPath, observability.ReasonNoPath},
		{"cancelled", context.Canceled, observability.ReasonCancelled},
		{"deadline", context.DeadlineExceeded, observability.ReasonTimeout},
		{"none", nil, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := classifyDriverFailure(testCase.err); got != testCase.want {
				t.Errorf("classifyDriverFailure = %q, want %q", got, testCase.want)
			}
		})
	}
}

// Cancellation and timeout are told apart.
//
// A caller that went away is a different outcome from a peer that never
// answered. Conflating them would make every clean shutdown look like a
// connectivity problem, which is the kind of noise that teaches an operator to
// ignore the log.
func TestCancellationIsNotReportedAsATimeout(t *testing.T) {
	if classifyDriverFailure(context.Canceled) == classifyDriverFailure(context.DeadlineExceeded) {
		t.Error("a cancelled session and one that timed out report the same reason")
	}
}

// An unchanged observation produces no record.
//
// The hold loop polls for the life of a session. A line per turn would be a line
// every few seconds forever, and the events worth reading would be buried in it.
func TestAnUnchangedObservationIsNotLogged(t *testing.T) {
	endpoint := netip.MustParseAddrPort("203.0.113.7:51820")
	at := time.Unix(1788000000, 0)

	state := wireguard.PeerState{
		Endpoint:      &endpoint,
		LastHandshake: at,
		ReceiveBytes:  1024,
		TransmitBytes: 2048,
	}

	if changed(state, state) {
		t.Error("an identical observation was reported as a change, so an idle tunnel would log forever")
	}
}

// Anything that moved produces a record.
func TestAChangedObservationIsLogged(t *testing.T) {
	first := netip.MustParseAddrPort("203.0.113.7:51820")
	second := netip.MustParseAddrPort("203.0.113.9:51820")
	at := time.Unix(1788000000, 0)

	base := wireguard.PeerState{Endpoint: &first, LastHandshake: at, ReceiveBytes: 1024}

	for name, mutate := range map[string]func(*wireguard.PeerState){
		"traffic arrived":      func(s *wireguard.PeerState) { s.ReceiveBytes = 2048 },
		"traffic left":         func(s *wireguard.PeerState) { s.TransmitBytes = 512 },
		"handshake refreshed":  func(s *wireguard.PeerState) { s.LastHandshake = at.Add(time.Minute) },
		"endpoint moved":       func(s *wireguard.PeerState) { s.Endpoint = &second },
		"endpoint disappeared": func(s *wireguard.PeerState) { s.Endpoint = nil },
	} {
		t.Run(name, func(t *testing.T) {
			current := base
			mutate(&current)

			if !changed(base, current) {
				t.Errorf("%s went unreported, so an operator would not see it", name)
			}
		})
	}
}

// A driver built without a logger logs nothing rather than panicking.
//
// The optional logger is the ordinary case for a test that does not care about
// output, so the nil path has to be the safe one.
func TestADriverWithoutALoggerDoesNotPanic(t *testing.T) {
	driver, _, _, _, peer := newDriverFixture(t, true)

	if driver.log == nil {
		t.Fatal("the driver's logger is nil, so every record would panic")
	}
	driver.log.Info("this must not panic", observability.Peer(peer), slog.String("k", "v"))
}
