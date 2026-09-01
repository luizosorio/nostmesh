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

	// outstanding maps a nonce to the challenge awaiting an answer.
	//
	// Keyed by nonce rather than by candidate, because a candidate is probed
	// once per round while a reply to the previous round may still be in
	// flight. Keying by candidate overwrites the earlier nonce, and the reply
	// that then arrives matches nothing and is discarded — on a fast path that
	// is most of them, and the candidate never verifies despite answering
	// correctly every time.
	//
	// Entries are removed on the answer that matches. An unanswered one stays
	// until the run ends, which is bounded: a candidate is probed at most
	// MaxAttemptsPerCandidate times and there are at most MaxCandidates of
	// them, so the map cannot outgrow their product.
	outstanding map[[NonceSize]byte]pendingCheck

	// counters guards the tallies below, separately from mu.
	//
	// They are diagnostics and share nothing with the outstanding challenges,
	// so a single lock would only create reentrancy: verifyResponse holds mu
	// across the whole match and still has to record what it discarded. A Go
	// mutex is not reentrant, and that combination deadlocks the receiving
	// goroutine on the first response that fails to authenticate.
	counters sync.Mutex

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
		outstanding: make(map[[NonceSize]byte]pendingCheck),
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

// pendingCheck is a challenge in flight and the candidate it probes.
type pendingCheck struct {
	candidateID string
	challenge   Challenge
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
	c.outstanding[challenge.Nonce] = pendingCheck{candidateID: candidate.ID, challenge: challenge}
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

		// The address it came from is worth more than any address we were
		// told about, because a packet actually traversed it. Learning it
		// happens only now, after the tag verified.
		c.learnPeerReflexive(arrival.source)

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
	c.counters.Lock()
	defer c.counters.Unlock()

	c.arrived++
}

// countDrop records why a datagram was discarded.
func (c *Checker) countDrop(reason string) {
	c.counters.Lock()
	defer c.counters.Unlock()

	c.dropped++
	if len(c.dropReasons) < maxDropReasons {
		c.dropReasons = append(c.dropReasons, reason)
	}
}

// learnPeerReflexive records the address an authenticated challenge came from.
//
// A peer behind NAT cannot know the address its own traffic will appear to come
// from: what STUN reported is the mapping toward the observer, and an
// address-dependent NAT uses a different one per destination. So the address
// that works is one neither side can announce — it only becomes knowable when a
// packet arrives through it.
//
// The candidate enters UNVERIFIED like every other. A datagram arriving from an
// address is not proof the address works in the other direction, and the
// challenge/response that follows is what settles that. Learning here only
// means the address gets probed at all: without it a NAT'd peer is answered
// indefinitely while every candidate we hold stays unreachable.
//
// Reachable only after DecodeChallenge verified the tag, so an off-path
// attacker cannot reach it whatever source address it spoofs. What remains is a
// session peer — someone already authorized — spending its own candidate
// budget: at most MaxThirdPartyCandidates addresses, probed
// MaxAttemptsPerCandidate times each, at probe size, toward addresses
// ValidateAddress permits. That bound is the same one srflx candidates from a
// lying observer already had, and answering still costs exactly one packet.
func (c *Checker) learnPeerReflexive(source netip.AddrPort) {
	// The engine takes its own lock, so this must not hold mu across the call:
	// verifyResponse already goes mu then engine, and acquiring them the other
	// way round here would complete a cycle.
	for _, known := range c.engine.Diagnostics() {
		if known.Address == source {
			// Already described, under whatever kind. Adding it again would
			// spend a third-party slot to probe the same address twice.
			return
		}
	}

	// The id is derived from the address so a peer that repeats a challenge
	// before the next probe round produces the same candidate rather than a new
	// one. AddCandidate treats a repeated id at the same address as a no-op.
	candidate := Candidate{
		ID:       fmt.Sprintf("prflx-%s", source),
		Kind:     KindPeerReflexive,
		Address:  source,
		Priority: priorityFor(KindPeerReflexive, source.Addr()),
		Source:   "peer probe",
	}

	// Refusal is a limit doing its job, not a reason to stop answering. It is
	// counted because a candidate table that quietly stopped growing and a peer
	// that never probed look identical from the outside.
	if err := c.engine.AddCandidate(candidate); err != nil {
		c.countDrop(fmt.Sprintf("could not learn %s: %v", source, err))
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

	c.counters.Lock()
	c.answered++
	c.counters.Unlock()
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

	// The nonce names the exact challenge this answers, so there is no scan and
	// no ambiguity about which round it belongs to.
	pending, known := c.outstanding[response.Nonce]
	if known {
		if err := VerifyResponse(pending.challenge, response); err == nil {
			// Confirm the datagram physically came back from the address
			// probed. The tag proves what the responder claimed; this proves
			// where it actually arrived from, and the two are independent.
			if !c.addressMatches(pending.candidateID, source) {
				c.countDrop(fmt.Sprintf("response for %s arrived from %s", pending.candidateID, source))
				return 0, false
			}

			roundTrip := c.clock().Sub(pending.challenge.SentAt)
			delete(c.outstanding, response.Nonce)

			if err := c.engine.RecordSuccess(pending.candidateID, roundTrip); err != nil {
				return 0, false
			}
			return roundTrip, true
		}
	}

	// Nothing matched. Counting it matters as much as the cases above: a
	// response for a challenge already answered, or one whose nonce belongs to
	// no outstanding probe, would otherwise vanish and leave the summary
	// reporting that nothing was discarded while discarding this.
	c.countDrop(fmt.Sprintf("response from %s matched no outstanding challenge", source))
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
	c.counters.Lock()
	defer c.counters.Unlock()

	if c.arrived == 0 && c.dropped == 0 {
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
