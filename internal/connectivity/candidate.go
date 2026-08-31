// Package connectivity discovers and validates UDP paths to a peer.
//
// The organising principle is that an address is a claim until this node has
// proved otherwise. A STUN observer, a peer, and a relay are all parties this
// node does not control; what any of them says about reachability is evidence
// of what they saw, not of what works from here.
package connectivity

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Kind names how a candidate was obtained.
//
// The distinction is not cosmetic: it says who vouched for the address, and
// therefore how much weight it carries before verification.
type Kind string

const (
	// KindHost is an address on a local interface. This node observed it
	// directly, so nobody had to be trusted for it to exist — though it still
	// has to be proved reachable *by the peer*.
	KindHost Kind = "host"

	// KindServerReflexive is an address a STUN observer reported.
	//
	// A third party said "I saw your packet come from here". That party may be
	// lying, mistaken, or reporting a mapping that only applies to traffic
	// toward itself.
	KindServerReflexive Kind = "srflx"

	// KindPeerReflexive is an address learned from a probe that arrived from
	// somewhere unexpected. It carries more weight than srflx, because the
	// packet actually reached this node.
	KindPeerReflexive Kind = "prflx"

	// KindStatic is an endpoint an operator configured. It is trusted as
	// operator intent, but still probed: the operator can be wrong about
	// reachability.
	KindStatic Kind = "static"

	// KindPortMapped is an address obtained through PCP or NAT-PMP, where the
	// router itself created the mapping.
	KindPortMapped Kind = "mapped"
)

var knownKinds = map[Kind]bool{
	KindHost:            true,
	KindServerReflexive: true,
	KindPeerReflexive:   true,
	KindStatic:          true,
	KindPortMapped:      true,
}

// IsKnown reports whether this build understands the kind.
func (k Kind) IsKnown() bool { return knownKinds[k] }

// RequiresThirdParty reports whether obtaining this kind involved trusting
// someone. Used to apply stricter attempt limits to what a stranger suggested.
func (k Kind) RequiresThirdParty() bool {
	return k == KindServerReflexive || k == KindPeerReflexive
}

// Status is how far a candidate has got toward being usable.
type Status string

const (
	// StatusUnverified means the address is a claim and nothing more.
	//
	// This is where every candidate starts, including ones this node
	// discovered itself: a local address existing says nothing about whether
	// the peer can reach it.
	StatusUnverified Status = "unverified"

	// StatusProbing means a challenge is outstanding.
	StatusProbing Status = "probing"

	// StatusValid means a challenge/response completed over this exact address
	// and port. Only this status permits a network effect.
	StatusValid Status = "valid"

	// StatusFailed means probing was tried and did not succeed. The reason is
	// kept, because "why did this not work" is the question an operator asks.
	StatusFailed Status = "failed"

	// StatusExpired means the candidate outlived its usefulness.
	StatusExpired Status = "expired"
)

// Permits reports whether a candidate in this status may affect the host.
//
// One status permits it. Everything else does not, and this function exists so
// that the check is a single named thing rather than a comparison repeated at
// every call site where it could be got wrong.
func (s Status) Permits() bool { return s == StatusValid }

var (
	// ErrUnverified reports an attempt to use a candidate that has not been
	// proved.
	ErrUnverified = errors.New("candidate has not been verified")

	// ErrUnsafeAddress reports an address that must never be probed.
	ErrUnsafeAddress = errors.New("address is not a safe probe target")

	// ErrTooManyCandidates reports a candidate set beyond its limit.
	ErrTooManyCandidates = errors.New("too many candidates")
)

// Candidate is one possible path to a peer.
type Candidate struct {
	// ID identifies the candidate within a session.
	ID string

	// Kind says how it was obtained.
	Kind Kind

	// Address is where to send.
	Address netip.AddrPort

	// Related is the local address a reflexive candidate derives from, which
	// is what makes it possible to tell two mappings of the same socket apart.
	Related netip.AddrPort

	// Foundation groups candidates that share a type and base, so that pairs
	// which would behave identically are not probed twice.
	Foundation string

	// Priority orders probing. Lower is tried first.
	Priority uint32

	// Status is how far verification has got.
	Status Status

	// Source names who supplied the address, for diagnostics. A candidate that
	// failed is more informative when the operator can see who suggested it.
	Source string

	// Attempts counts probes sent. Bounding this is what stops an observer's
	// lie from turning this node into a traffic source aimed at a victim.
	Attempts int

	// FailureReason explains a failed candidate in operator terms.
	FailureReason string

	DiscoveredAt time.Time
	VerifiedAt   *time.Time
	ExpiresAt    time.Time
}

// IsExpired reports whether the candidate has outlived its window.
func (c Candidate) IsExpired(now time.Time) bool { return !now.Before(c.ExpiresAt) }

// CanProbe reports whether another probe is permitted.
func (c Candidate) CanProbe(now time.Time, maxAttempts int) bool {
	switch {
	case c.Status == StatusValid, c.Status == StatusExpired:
		return false
	case c.IsExpired(now):
		return false
	case c.Attempts >= maxAttempts:
		return false
	default:
		return true
	}
}

// String renders the candidate for diagnostics.
func (c Candidate) String() string {
	return fmt.Sprintf("%s %s %s [%s]", c.ID, c.Kind, c.Address, c.Status)
}

// ValidateAddress reports whether an address may be probed at all.
//
// This is the check that turns a lying observer from a weapon into a nuisance.
// An observer that reports a victim's address — or a loopback, a link-local, or
// a broadcast address — must not be able to make this node send anything there.
// The filter runs before a candidate is even recorded.
func ValidateAddress(addr netip.AddrPort) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: address is not valid", ErrUnsafeAddress)
	}
	if addr.Port() == 0 {
		return fmt.Errorf("%w: port is zero", ErrUnsafeAddress)
	}

	ip := addr.Addr().Unmap()

	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("%w: unspecified address %s", ErrUnsafeAddress, ip)
	case ip.IsLoopback():
		// Probing loopback would target this host's own services.
		return fmt.Errorf("%w: loopback address %s", ErrUnsafeAddress, ip)
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast():
		// A multicast target turns one probe into many packets.
		return fmt.Errorf("%w: multicast address %s", ErrUnsafeAddress, ip)
	case ip.IsLinkLocalUnicast():
		// Link-local requires a zone to be meaningful and is not routable.
		return fmt.Errorf("%w: link-local address %s", ErrUnsafeAddress, ip)
	}

	return nil
}

// IsPrivate reports whether an address is in private space.
//
// Private addresses are legitimate candidates on a shared LAN and useless
// across the internet. The caller decides which case applies; this only
// reports the fact.
func IsPrivate(addr netip.Addr) bool {
	ip := addr.Unmap()
	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
