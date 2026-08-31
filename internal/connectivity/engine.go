package connectivity

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Limits bound what a session may attempt.
//
// These are not tuning knobs. An observer that reports a victim's address turns
// this node into a source of unsolicited traffic aimed at that victim, and the
// only thing standing between a lie and an amplification attack is how many
// packets this node is willing to send before giving up.
type Limits struct {
	// MaxCandidates bounds the candidate set for one session.
	MaxCandidates int

	// MaxAttemptsPerCandidate bounds probes to a single address.
	MaxAttemptsPerCandidate int

	// MaxThirdPartyCandidates bounds how many addresses a stranger may
	// contribute. A peer or observer that floods candidates must not be able
	// to spend this node's bandwidth on their behalf.
	MaxThirdPartyCandidates int

	// GatherTimeout bounds discovery.
	GatherTimeout time.Duration

	// CheckTimeout bounds how long one probe waits for a response.
	CheckTimeout time.Duration

	// TotalTimeout bounds the whole attempt, so a session that cannot connect
	// fails rather than looping. There is no data relay yet: a direct failure
	// must terminate clearly.
	TotalTimeout time.Duration
}

// DefaultLimits returns conservative bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxCandidates:           32,
		MaxAttemptsPerCandidate: 5,
		MaxThirdPartyCandidates: 8,
		GatherTimeout:           5 * time.Second,
		CheckTimeout:            500 * time.Millisecond,
		TotalTimeout:            30 * time.Second,
	}
}

var (
	// ErrNoValidPath reports that no candidate could be verified.
	ErrNoValidPath = errors.New("no candidate could be verified")

	// ErrGatherTimeout reports discovery running out of time.
	ErrGatherTimeout = errors.New("candidate gathering timed out")
)

// Engine tracks candidates for one session and decides what to probe.
//
// It makes decisions and records outcomes; it does not send packets. The
// transport does that, which keeps every rule here testable without a network.
type Engine struct {
	mu sync.Mutex

	sessionID  string
	limits     Limits
	candidates map[string]*Candidate
	clock      func() time.Time

	// thirdPartyCount tracks how many candidates came from strangers, so the
	// limit applies to the source rather than the total.
	thirdPartyCount int

	// nominated is the winning candidate, once one is verified.
	nominated *Candidate

	startedAt time.Time
}

// EngineOptions configures an Engine.
type EngineOptions struct {
	SessionID string
	Limits    Limits
	Clock     func() time.Time
}

// NewEngine builds an Engine.
func NewEngine(opts EngineOptions) (*Engine, error) {
	if opts.SessionID == "" {
		return nil, errors.New("engine requires a session id")
	}
	if opts.Limits.MaxCandidates <= 0 {
		opts.Limits = DefaultLimits()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &Engine{
		sessionID:  opts.SessionID,
		limits:     opts.Limits,
		candidates: make(map[string]*Candidate),
		clock:      opts.Clock,
		startedAt:  opts.Clock(),
	}, nil
}

// AddCandidate records a candidate, refusing unsafe or excessive ones.
//
// Every candidate enters as UNVERIFIED regardless of where it came from,
// including addresses this node discovered on its own interfaces: a local
// address existing says nothing about whether the peer can reach it.
func (e *Engine) AddCandidate(candidate Candidate) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := ValidateAddress(candidate.Address); err != nil {
		return err
	}
	if !candidate.Kind.IsKnown() {
		return fmt.Errorf("unknown candidate kind %q", candidate.Kind)
	}
	if candidate.ID == "" {
		return errors.New("candidate requires an id")
	}

	if existing, known := e.candidates[candidate.ID]; known {
		// A repeated candidate is not an error — relays duplicate — but its
		// address must not change under the same id.
		if existing.Address != candidate.Address {
			return fmt.Errorf("candidate %s already refers to %s", candidate.ID, existing.Address)
		}
		return nil
	}

	if len(e.candidates) >= e.limits.MaxCandidates {
		return fmt.Errorf("%w: %d candidates", ErrTooManyCandidates, len(e.candidates))
	}

	if candidate.Kind.RequiresThirdParty() {
		if e.thirdPartyCount >= e.limits.MaxThirdPartyCandidates {
			return fmt.Errorf("%w: %d third-party candidates, limit is %d",
				ErrTooManyCandidates, e.thirdPartyCount, e.limits.MaxThirdPartyCandidates)
		}
		e.thirdPartyCount++
	}

	// Status is forced rather than taken from the caller. A candidate arriving
	// pre-marked valid is exactly what an attacker would send.
	candidate.Status = StatusUnverified
	candidate.Attempts = 0
	candidate.VerifiedAt = nil
	candidate.DiscoveredAt = e.clock()

	if candidate.ExpiresAt.IsZero() {
		candidate.ExpiresAt = e.clock().Add(e.limits.TotalTimeout)
	}
	if candidate.Foundation == "" {
		candidate.Foundation = foundationFor(candidate)
	}

	stored := candidate
	e.candidates[candidate.ID] = &stored
	return nil
}

// Probable returns candidates worth probing, in priority order.
//
// Foundations are deduplicated: two candidates sharing a type and base would
// behave identically, so probing both spends packets to learn one thing.
func (e *Engine) Probable() []Candidate {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock()
	seenFoundation := make(map[string]bool)
	probable := make([]Candidate, 0, len(e.candidates))

	for _, candidate := range e.candidates {
		if !candidate.CanProbe(now, e.limits.MaxAttemptsPerCandidate) {
			continue
		}
		if seenFoundation[candidate.Foundation] {
			continue
		}
		seenFoundation[candidate.Foundation] = true
		probable = append(probable, *candidate)
	}

	sort.Slice(probable, func(i, j int) bool {
		if probable[i].Priority != probable[j].Priority {
			return probable[i].Priority < probable[j].Priority
		}
		return probable[i].ID < probable[j].ID
	})
	return probable
}

// RecordAttempt notes that a probe was sent.
func (e *Engine) RecordAttempt(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate, known := e.candidates[id]
	if !known {
		return fmt.Errorf("unknown candidate %s", id)
	}

	candidate.Attempts++
	candidate.Status = StatusProbing
	return nil
}

// RecordSuccess promotes a candidate to valid.
//
// This is the only path to StatusValid, and it exists so that promotion is a
// single named operation the caller has to reach deliberately.
func (e *Engine) RecordSuccess(id string, roundTrip time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate, known := e.candidates[id]
	if !known {
		return fmt.Errorf("unknown candidate %s", id)
	}

	now := e.clock()
	candidate.Status = StatusValid
	candidate.VerifiedAt = &now

	// The first verified candidate wins. Priority ordering already put the
	// preferred paths first, so the first success is the best available.
	if e.nominated == nil {
		e.nominated = candidate
	}
	return nil
}

// RecordFailure marks a candidate failed, with a reason an operator can act on.
func (e *Engine) RecordFailure(id, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	candidate, known := e.candidates[id]
	if !known {
		return fmt.Errorf("unknown candidate %s", id)
	}

	if candidate.Attempts >= e.limits.MaxAttemptsPerCandidate {
		candidate.Status = StatusFailed
		candidate.FailureReason = reason
		return nil
	}

	// Attempts remain: back to unverified so it is retried.
	candidate.Status = StatusUnverified
	candidate.FailureReason = reason
	return nil
}

// Nominated returns the winning candidate, or nil if none is verified.
//
// A nil result means nothing may be applied to the host. There is no fallback
// to "the best unverified one", because that would defeat the entire model.
func (e *Engine) Nominated() *Candidate {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.nominated == nil {
		return nil
	}
	nominated := *e.nominated
	return &nominated
}

// Endpoint returns the address to configure, and whether one is available.
//
// It refuses to return anything unverified. A caller that ignores the boolean
// gets a zero value rather than an address, so forgetting the check produces an
// obvious failure rather than a subtle one.
func (e *Engine) Endpoint() (netip.AddrPort, bool) {
	nominated := e.Nominated()
	if nominated == nil || !nominated.Status.Permits() {
		return netip.AddrPort{}, false
	}
	return nominated.Address, true
}

// Diagnostics returns every candidate and what happened to it.
//
// "Why did this not connect" is the question an operator asks, and answering
// it needs the failures, not just the successes.
func (e *Engine) Diagnostics() []Candidate {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock()
	report := make([]Candidate, 0, len(e.candidates))

	for _, candidate := range e.candidates {
		entry := *candidate
		if entry.Status != StatusValid && entry.IsExpired(now) {
			entry.Status = StatusExpired
			if entry.FailureReason == "" {
				entry.FailureReason = "expired before verification"
			}
		}
		report = append(report, entry)
	}

	sort.Slice(report, func(i, j int) bool { return report[i].Priority < report[j].Priority })
	return report
}

// IsExhausted reports whether there is nothing left to try.
//
// There is no data relay yet, so a session with nothing left to probe must fail
// clearly rather than loop. This covers only the candidate set; running out of
// time is a separate question, because a session with probes outstanding
// should process their answers before giving up.
func (e *Engine) IsExhausted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.nominated != nil {
		return false
	}

	now := e.clock()
	for _, candidate := range e.candidates {
		if candidate.CanProbe(now, e.limits.MaxAttemptsPerCandidate) {
			return false
		}
	}
	return true
}

// IsTimedOut reports whether the attempt has run out of time.
func (e *Engine) IsTimedOut() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.nominated != nil {
		return false
	}
	return e.clock().Sub(e.startedAt) > e.limits.TotalTimeout
}

// Count returns how many candidates are tracked.
func (e *Engine) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.candidates)
}

// foundationFor groups candidates that would behave identically.
func foundationFor(candidate Candidate) string {
	base := candidate.Related.Addr()
	if !base.IsValid() {
		base = candidate.Address.Addr()
	}
	return fmt.Sprintf("%s|%s", candidate.Kind, base)
}
