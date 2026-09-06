package observability

import (
	"net/netip"
	"strconv"
	"strings"
)

// Diagnostic is the explicit opt-in required before an address is written out
// in full.
//
// It is deliberately not a log level. Raising verbosity to work out why a
// handshake stalls is routine; consenting to write peer addresses to disk is
// not, and collapsing the two would make the second happen by accident every
// time somebody did the first.
//
// This is the "modo diagnóstico explícito" the operations documentation
// requires before a private address may be recorded. See NM-22.
type Diagnostic uint8

const (
	// DiagnosticOff reduces every address. A public one keeps its network, a
	// private one is named by its kind alone.
	DiagnosticOff Diagnostic = iota

	// DiagnosticAddresses records addresses in full, including RFC1918.
	DiagnosticAddresses
)

// Diagnostic mode names, as they appear in configuration.
const (
	DiagnosticNameOff       = "off"
	DiagnosticNameAddresses = "addresses"
)

// ParseDiagnostic maps a configured name, defaulting to off.
//
// An unrecognised name takes the closed setting rather than the open one:
// getting more disclosure than asked for is the failure that cannot be undone,
// because the log is already written. Configuration validation reports the typo
// separately.
func ParseDiagnostic(name string) Diagnostic {
	if strings.EqualFold(strings.TrimSpace(name), DiagnosticNameAddresses) {
		return DiagnosticAddresses
	}
	return DiagnosticOff
}

// String names the mode for a log line.
func (d Diagnostic) String() string {
	if d == DiagnosticAddresses {
		return DiagnosticNameAddresses
	}
	return DiagnosticNameOff
}

// Address kinds, used when an address is reduced rather than printed.
//
// The kind is what a reader actually needs from a redacted address: whether the
// path being tried was a local one, a carrier-NAT one or a public one is the
// question a NAT traversal problem turns on, and none of it identifies a host.
const (
	addrPrivate    = "private"
	addrLoopback   = "loopback"
	addrLinkLocal  = "link-local"
	addrCGNAT      = "cgnat"
	addrUnroutable = "unroutable"
	addrInvalid    = "invalid"
)

// cgnatV4 is the carrier-grade NAT range from RFC 6598.
//
// Worth naming separately from the private ranges: an address here means the
// peer is behind a provider's NAT rather than its own, which changes what a
// traversal failure means and what can be done about it.
var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// redactAddr reduces an address to what may be logged without the gate.
//
// A public address keeps its network, which is enough to tell two paths apart
// and to recognise a provider, without naming a host. A private one is reduced
// to its kind, since inside a private range the host part is the whole of the
// identifying information.
func redactAddr(addr netip.Addr) string {
	ip := addr.Unmap()

	switch {
	case !ip.IsValid():
		return addrInvalid
	case ip.IsLoopback():
		return addrLoopback
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return addrLinkLocal
	case ip.IsPrivate():
		return addrPrivate
	case ip.Is4() && cgnatV4.Contains(ip):
		return addrCGNAT
	case !ip.IsGlobalUnicast():
		return addrUnroutable
	}

	// A public address keeps its network and loses its host. The /24 and /48
	// boundaries are the conventional ones for saying "this network" without
	// saying "this machine".
	bits := 24
	if ip.Is6() {
		bits = 48
	}
	network, err := ip.Prefix(bits)
	if err != nil {
		return addrUnroutable
	}
	return network.String()
}

// renderAddrPort renders an address and port under the given mode.
//
// The port survives redaction. It says which service was being reached and is
// the same for every host behind a NAT, so it distinguishes paths without
// identifying anyone.
func renderAddrPort(addr netip.AddrPort, mode Diagnostic) string {
	if !addr.IsValid() {
		return addrInvalid
	}
	if mode == DiagnosticAddresses {
		return addr.String()
	}
	return redactAddr(addr.Addr()) + ":" + strconv.Itoa(int(addr.Port()))
}

// renderPrefix renders a network prefix under the given mode.
//
// AllowedIPs are derived from local policy rather than received from a peer, so
// they describe this node's own configuration. They are still reduced when the
// gate is closed: an overlay prefix names the private network being built, and
// that is the operator's to disclose.
func renderPrefix(prefix netip.Prefix, mode Diagnostic) string {
	if !prefix.IsValid() {
		return addrInvalid
	}
	if mode == DiagnosticAddresses {
		return prefix.String()
	}
	return redactAddr(prefix.Addr()) + "/" + strconv.Itoa(prefix.Bits())
}
