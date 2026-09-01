package connectivity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Transport sends and receives probe datagrams.
//
// It is an interface so the checking logic can be tested without a network:
// every rule about what gets probed, how often, and what counts as proof is
// decided here, and a fake transport makes each of them assertable.
type Transport interface {
	// Send transmits a probe to an address.
	Send(ctx context.Context, target netip.AddrPort, payload []byte) error

	// Receive returns the next probe to arrive, with its source address.
	Receive(ctx context.Context) (payload []byte, source netip.AddrPort, err error)
}

// Checker runs connectivity checks against candidates.
//
// It is the only thing that can promote a candidate to VALID, and it does so
// only after a response authenticated with the session key arrives from the
// exact address probed.
type Checker struct {
	mu sync.Mutex

	engine    *Engine
	transport Transport
	key       SessionKey
	limits    Limits
	clock     func() time.Time

	// outstanding maps a candidate id to the challenge awaiting an answer.
	outstanding map[string]Challenge

	// arrived and dropped separate "nothing came back" from "something came
	// back and we discarded it", which have opposite causes.
	arrived     int
	dropped     int
	dropReasons []string
	answered    int
}

// CheckerOptions configures a Checker.
type CheckerOptions struct {
	Engine    *Engine
	Transport Transport
	Key       SessionKey
	Limits    Limits
	Clock     func() time.Time
}

// NewChecker builds a Checker.
func NewChecker(opts CheckerOptions) (*Checker, error) {
	if opts.Engine == nil {
		return nil, errors.New("checker requires an engine")
	}
	if opts.Transport == nil {
		return nil, errors.New("checker requires a transport")
	}
	if opts.Limits.MaxAttemptsPerCandidate <= 0 {
		opts.Limits = DefaultLimits()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &Checker{
		engine:      opts.Engine,
		transport:   opts.Transport,
		key:         opts.Key,
		limits:      opts.Limits,
		clock:       opts.Clock,
		outstanding: make(map[string]Challenge),
	}, nil
}

// CheckResult reports what a round of checking achieved.
type CheckResult struct {
	// Nominated is the winning candidate, or nil if none was verified.
	Nominated *Candidate

	// Probed counts challenges sent.
	Probed int

	// RoundTrip is how long the winning response took, which is the only
	// latency figure this node measured rather than was told.
	RoundTrip time.Duration
}

// Run probes candidates until one is verified or the attempt is exhausted.
//
// There is no data relay yet, so exhaustion has to be a clear ending: a session
// that cannot connect fails rather than retrying forever.
func (c *Checker) Run(ctx context.Context) (CheckResult, error) {
	result := CheckResult{}

	// The deadline is a duration rather than an absolute time, because the
	// injected clock is not the one context compares against: a test clock set
	// to a future date would produce a context that is already expired, and one
	// set to the past would never expire. The engine enforces the timeout
	// against the injected clock; this only bounds the goroutine.
	ctx, cancel := context.WithTimeout(ctx, c.limits.TotalTimeout)
	defer cancel()

	responses := make(chan probeArrival, 16)
	go c.receive(ctx, responses)

	for {
		if ctx.Err() != nil {
			// Running out of time is a form of exhaustion, and the operator
			// needs the same diagnosis either way: which candidates were tried,
			// who suggested each, and why each failed.
			return result, c.exhaustionError()
		}
		// A verified candidate is checked first: a probe that succeeded must
		// not be discarded because the next clock reading crossed a deadline.
		if nominated := c.engine.Nominated(); nominated != nil {
			result.Nominated = nominated
			return result, nil
		}

		if c.engine.IsExhausted() || c.engine.IsTimedOut() {
			return result, c.exhaustionError()
		}

		probable := c.engine.Probable()
		if len(probable) == 0 {
			return result, c.exhaustionError()
		}

		for _, candidate := range probable {
			if err := c.sendChallenge(ctx, candidate); err != nil {
				_ = c.engine.RecordFailure(candidate.ID, err.Error())
				continue
			}
			result.Probed++
		}

		// Wait for an answer, then loop: a response may arrive for any
		// outstanding challenge, not only the last one sent.
		roundTrip, verified := c.awaitResponse(ctx, responses)
		if verified {
			result.RoundTrip = roundTrip
		}
	}
}

type probeArrival struct {
	payload []byte
	source  netip.AddrPort
}

// receive reads probes until the context ends.
func (c *Checker) receive(ctx context.Context, out chan<- probeArrival) {
	defer close(out)

	for {
		payload, source, err := c.transport.Receive(ctx)
		if err != nil {
			return
		}

		select {
		case out <- probeArrival{payload: payload, source: source}:
		case <-ctx.Done():
			return
		}
	}
}

// sendChallenge probes one candidate.
func (c *Checker) sendChallenge(ctx context.Context, candidate Candidate) error {
	challenge, err := NewChallenge(c.clock())
	if err != nil {
		return err
	}

	payload := EncodeChallenge(challenge, c.key)

	if err := c.engine.RecordAttempt(candidate.ID); err != nil {
		return err
	}
	if err := c.transport.Send(ctx, candidate.Address, payload); err != nil {
		return fmt.Errorf("sending probe: %w", err)
	}

	c.mu.Lock()
	c.outstanding[candidate.ID] = challenge
	c.mu.Unlock()

	return nil
}

// awaitResponse waits briefly for a probe and processes it.
func (c *Checker) awaitResponse(ctx context.Context, responses <-chan probeArrival) (time.Duration, bool) {
	timer := time.NewTimer(c.limits.CheckTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return 0, false
	case <-timer.C:
		return 0, false
	case arrival, open := <-responses:
		if !open {
			return 0, false
		}
		return c.handleArrival(arrival)
	}
}

// handleArrival processes one received probe.
//
// A probe that fails authentication is discarded without a trace in the
// candidate state: responding to it, or recording it, would let an attacker
// learn something by sending garbage.
func (c *Checker) handleArrival(arrival probeArrival) (time.Duration, bool) {
	c.countArrival()

	// The kind decides which verifier applies, because the two directions
	// authenticate different things: a challenge carries no address, while a
	// response is bound to the address the challenger probed. The kind byte is
	// itself covered by the tag, so a probe that lies about it authenticates as
	// neither.
	isResponse, err := ProbeKind(arrival.payload)
	if err != nil {
		c.countDrop(fmt.Sprintf("%v (first bytes %x, from %s)",
			err, arrival.payload[:min(12, len(arrival.payload))], arrival.source))
		return 0, false
	}

	if !isResponse {
		challenge, decodeErr := DecodeChallenge(arrival.payload, c.key)
		if decodeErr != nil {
			c.countDrop("challenge did not authenticate")
			return 0, false
		}

		// A challenge from the peer. Answering it is what lets the peer verify
		// its own candidate, and it costs one packet no larger than what
		// arrived.
		c.answer(challenge, arrival.source)
		return 0, false
	}

	return c.verifyResponse(arrival.payload, arrival.source)
}

// countArrival records that a datagram reached the checker.
//
// A probe that never arrives and one that arrives and is discarded look
// identical from outside: the candidate simply never verifies. Counting them
// apart is what turns "no candidate could be verified" into a diagnosis.
func (c *Checker) countArrival() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.arrived++
}

// countDrop records why a datagram was discarded.
func (c *Checker) countDrop(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.dropped++
	if len(c.dropReasons) < maxDropReasons {
		c.dropReasons = append(c.dropReasons, reason)
	}
}

// answer responds to a peer's challenge.
func (c *Checker) answer(challenge DecodedProbe, source netip.AddrPort) {
	payload := EncodeResponse(challenge.Nonce, c.clock(), source, c.key)

	// A failure here is not fatal — the peer retries, and its own limits bound
	// that — but it must not be invisible. An answer that never leaves looks
	// exactly like a peer that never replied, and the two have opposite causes:
	// one is a local socket problem, the other is the network.
	if err := c.transport.Send(context.Background(), source, payload); err != nil {
		c.countDrop(fmt.Sprintf("could not answer %s: %v", source, err))
		return
	}

	c.mu.Lock()
	c.answered++
	c.mu.Unlock()
}

// verifyResponse matches a response to its challenge and promotes the candidate.
//
// The response must have arrived from the exact address probed, which
// DecodeProbe already enforced by authenticating over the source address.
func (c *Checker) verifyResponse(payload []byte, source netip.AddrPort) (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	response, err := DecodeResponse(payload, c.key)
	if err != nil {
		c.countDrop("response did not authenticate")
		return 0, false
	}

	for id, challenge := range c.outstanding {
		if err := VerifyResponse(challenge, response); err != nil {
			continue
		}

		// Confirm the datagram physically came back from the address probed.
		// The tag proves what the responder claimed; this proves where it
		// actually arrived from, and the two are independent.
		if !c.addressMatches(id, source) {
			c.countDrop(fmt.Sprintf("response for %s arrived from %s", id, source))
			continue
		}

		roundTrip := c.clock().Sub(challenge.SentAt)
		delete(c.outstanding, id)

		if err := c.engine.RecordSuccess(id, roundTrip); err != nil {
			return 0, false
		}
		return roundTrip, true
	}

	return 0, false
}

// candidateAddress returns the address a candidate was probed at.
func (c *Checker) candidateAddress(id string) (netip.AddrPort, bool) {
	for _, candidate := range c.engine.Diagnostics() {
		if candidate.ID == id {
			return candidate.Address, true
		}
	}
	return netip.AddrPort{}, false
}

// addressMatches reports whether a candidate is at the given address.
func (c *Checker) addressMatches(id string, source netip.AddrPort) bool {
	address, known := c.candidateAddress(id)
	return known && address == source
}

// traffic describes what the checker saw on the wire.
func (c *Checker) traffic() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.arrived == 0 {
		return "nothing arrived on the probe socket"
	}

	summary := fmt.Sprintf("%d datagram(s) arrived, %d answered, %d discarded",
		c.arrived, c.answered, c.dropped)
	if len(c.dropReasons) > 0 {
		summary += ": " + strings.Join(c.dropReasons, "; ")
	}
	return summary
}

// maxDropReasons bounds the detail kept, so a flood cannot grow it.
const maxDropReasons = 4

// exhaustionError explains why no path was found.
//
// "Could not connect" is useless to an operator. This says which candidates
// were tried, who suggested each, and why each failed.
func (c *Checker) exhaustionError() error {
	diagnostics := c.engine.Diagnostics()
	if len(diagnostics) == 0 {
		return fmt.Errorf("%w: no candidates were discovered", ErrNoValidPath)
	}

	summary := make([]string, 0, len(diagnostics))
	for _, candidate := range diagnostics {
		reason := candidate.FailureReason
		if reason == "" {
			reason = string(candidate.Status)
		}
		summary = append(summary, fmt.Sprintf("%s (%s, from %s): %s",
			candidate.Address, candidate.Kind, sourceOr(candidate.Source), reason))
	}

	// What reached the socket separates "the peer never answered" from "it
	// answered and we discarded it", which have opposite causes and would
	// otherwise be reported identically.
	return fmt.Errorf("%w after %d candidates (%s):\n  %s",
		ErrNoValidPath, len(diagnostics), c.traffic(), joinLines(summary))
}

func sourceOr(source string) string {
	if source == "" {
		return "unknown"
	}
	return source
}

func joinLines(lines []string) string {
	out := ""
	for i, line := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += line
	}
	return out
}
