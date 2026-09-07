package domain

import (
	"errors"
	"fmt"
	"net/netip"
)

// Which announced prefixes a node will even consider.
//
// These run before policy, and they refuse things no policy should be able to
// permit: a prefix that could not be a legitimate destination, or one whose
// installation would break the connection carrying it. Policy answers "may this
// peer route this"; this answers "could this prefix be routed at all". See
// NM-25.

// ErrRouteRefused reports an announced prefix this node will not consider.
var ErrRouteRefused = errors.New("route refused")

// LocalNetwork describes what this host must not let an announcement capture.
//
// The addresses are gathered locally and never come from a peer. A peer that
// could influence this list could route around the very check meant to stop it.
type LocalNetwork struct {
	// Transports are the addresses this node's tunnels run over.
	//
	// A route covering one of these sends the tunnel's own packets into the
	// tunnel: the loop the architecture names explicitly.
	Transports []netip.Addr

	// Infrastructure are relays and STUN observers.
	//
	// Same loop, one step removed. Losing the path to a relay takes the control
	// plane with it, and the node cannot then be told to withdraw the route
	// that broke it.
	Infrastructure []netip.Addr

	// Prefixes are destinations this host already reaches, including its own
	// addresses and the overlay it holds.
	Prefixes []netip.Prefix
}

// AdmitRoute reports whether an announced prefix may be considered.
//
// Refusals are ordered cheapest first, and each names what it refused rather
// than returning a bare error: an operator seeing "route refused" and nothing
// else has to guess which rule fired.
func AdmitRoute(prefix netip.Prefix, local LocalNetwork) error {
	if !prefix.IsValid() {
		return fmt.Errorf("%w: prefix is not valid", ErrRouteRefused)
	}
	if prefix != prefix.Masked() {
		return fmt.Errorf("%w: prefix %s is not in canonical form", ErrRouteRefused, prefix)
	}

	// A default route captures everything, including the tunnel's own
	// transport. NM-25 keeps it refused for this MVP: policy can decide an
	// operator is willing to be asked, and there is nowhere to ask.
	if prefix.Bits() == 0 {
		return fmt.Errorf("%w: %s is a default route", ErrRouteRefused, prefix)
	}

	if err := admitAddress(prefix.Addr()); err != nil {
		return err
	}

	// A prefix covering a transport endpoint routes the tunnel into itself.
	for _, transport := range local.Transports {
		if prefix.Contains(transport.Unmap()) {
			return fmt.Errorf("%w: %s covers this node's tunnel transport", ErrRouteRefused, prefix)
		}
	}
	for _, address := range local.Infrastructure {
		if prefix.Contains(address.Unmap()) {
			return fmt.Errorf("%w: %s covers a relay or observer this node depends on", ErrRouteRefused, prefix)
		}
	}

	// A destination this host already reaches is not the announcer's to offer.
	// Overlapping either way is refused: a narrower announcement would steal
	// part of a local network by longest-prefix match, and a wider one would
	// swallow it whole.
	for _, mine := range local.Prefixes {
		if prefix.Overlaps(mine) {
			return fmt.Errorf("%w: %s overlaps %s, which this host already reaches",
				ErrRouteRefused, prefix, mine)
		}
	}

	return nil
}

// admitAddress refuses prefixes rooted at an address nothing legitimate
// announces.
//
// The same families the connectivity layer refuses for a candidate, for the
// same reason: an address that cannot be a destination cannot be a route.
func admitAddress(addr netip.Addr) error {
	ip := addr.Unmap()

	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("%w: unspecified address %s", ErrRouteRefused, ip)
	case ip.IsLoopback():
		return fmt.Errorf("%w: loopback address %s", ErrRouteRefused, ip)
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("%w: multicast address %s", ErrRouteRefused, ip)
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("%w: link-local address %s", ErrRouteRefused, ip)
	}

	return nil
}
