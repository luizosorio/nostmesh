package observability

import (
	"net/netip"
	"strings"
	"testing"
)

// With the gate closed, a private address is reduced to its kind.
//
// This is the rule the operations documentation states: a private address needs
// an explicit diagnostic mode before it is recorded. The host part inside a
// private range is the whole of the identifying information, so nothing of it
// survives.
func TestTheGateRedactsPrivateAddresses(t *testing.T) {
	for _, address := range []string{
		"192.168.1.50:51820",
		"10.20.30.40:51820",
		"172.16.5.9:51820",
		"[fd12:3456:789a::1]:51820",
	} {
		t.Run(address, func(t *testing.T) {
			rendered := renderAddrPort(netip.MustParseAddrPort(address), DiagnosticOff)

			host, _, _ := strings.Cut(address, "]:")
			host = strings.TrimPrefix(host, "[")
			if before, _, found := strings.Cut(host, ":"); found {
				host = before
			}

			if strings.Contains(rendered, host) {
				t.Errorf("the address survived redaction: %s", rendered)
			}
			if !strings.HasSuffix(rendered, ":51820") {
				t.Errorf("the port was redacted too, and it identifies nobody: %s", rendered)
			}
		})
	}
}

// A public address keeps its network and loses its host.
//
// Enough to tell two paths apart and recognise a provider; not enough to name a
// machine.
func TestTheGateKeepsThePublicNetwork(t *testing.T) {
	rendered := renderAddrPort(netip.MustParseAddrPort("203.0.113.7:51820"), DiagnosticOff)

	if !strings.HasPrefix(rendered, "203.0.113.0/24") {
		t.Errorf("the network was lost, so two paths cannot be told apart: %s", rendered)
	}
	if strings.Contains(rendered, "203.0.113.7") {
		t.Errorf("the host survived redaction: %s", rendered)
	}
}

// Opening the gate records the address in full.
//
// The point of the mode is that the reduced form is not enough to diagnose NAT
// traversal, so the open form has to be genuinely complete.
func TestOpeningTheGateRecordsTheWholeAddress(t *testing.T) {
	for _, address := range []string{"192.168.1.50:51820", "203.0.113.7:51820"} {
		rendered := renderAddrPort(netip.MustParseAddrPort(address), DiagnosticAddresses)
		if rendered != address {
			t.Errorf("with the gate open, got %q, want %q", rendered, address)
		}
	}
}

// The redaction distinguishes the kinds of address a reader needs to tell apart.
//
// Whether a path is loopback, a private network or a carrier NAT is the question
// a traversal failure turns on, and none of those answers identifies a host.
func TestRedactionNamesTheKindOfAddress(t *testing.T) {
	for address, want := range map[string]string{
		"127.0.0.1:51820":    addrLoopback,
		"192.168.1.50:51820": addrPrivate,
		"100.64.0.5:51820":   addrCGNAT,
		"[fe80::1]:51820":    addrLinkLocal,
		"[fd00::1]:51820":    addrPrivate,
	} {
		got := renderAddrPort(netip.MustParseAddrPort(address), DiagnosticOff)
		if !strings.HasPrefix(got, want) {
			t.Errorf("%s rendered as %q, want it named as %q", address, got, want)
		}
	}
}

// An unparseable or zero address says so rather than rendering as something.
func TestAnInvalidAddressIsNamedAsInvalid(t *testing.T) {
	if got := renderAddrPort(netip.AddrPort{}, DiagnosticAddresses); got != addrInvalid {
		t.Errorf("the zero address rendered as %q", got)
	}
	if got := renderCandidateAddress("not-an-address", DiagnosticOff); got != addrInvalid {
		t.Errorf("an unparseable candidate address rendered as %q; peer-supplied text must not be echoed", got)
	}
}

// A candidate address that a peer sent is never echoed verbatim when it does
// not parse.
//
// It arrived from outside, so echoing it is how peer-controlled content reaches
// a log — which the protocol documentation forbids.
func TestAnUnparseableCandidateAddressIsNotEchoed(t *testing.T) {
	hostile := "attacker-controlled-value-that-must-not-appear"

	if got := renderCandidateAddress(hostile, DiagnosticAddresses); strings.Contains(got, hostile) {
		t.Errorf("peer-supplied text was echoed into the log: %q", got)
	}
}

// The mode defaults closed, including for an unrecognised name.
//
// Getting more disclosure than asked for is the failure that cannot be undone,
// because the log is already written.
func TestAnUnknownDiagnosticModeIsClosed(t *testing.T) {
	for _, name := range []string{"", "on", "true", "full", "nonsense", "ADDRESS"} {
		if got := ParseDiagnostic(name); got != DiagnosticOff {
			t.Errorf("ParseDiagnostic(%q) = %v, want off", name, got)
		}
	}
}

func TestTheAddressesModeParses(t *testing.T) {
	for _, name := range []string{"addresses", "ADDRESSES", " addresses "} {
		if got := ParseDiagnostic(name); got != DiagnosticAddresses {
			t.Errorf("ParseDiagnostic(%q) = %v, want addresses", name, got)
		}
	}
}

// A prefix is reduced the same way an address is.
func TestPrefixesAreRedactedToo(t *testing.T) {
	rendered := renderPrefix(netip.MustParsePrefix("10.20.30.0/24"), DiagnosticOff)

	if strings.Contains(rendered, "10.20.30") {
		t.Errorf("an overlay prefix survived redaction: %s", rendered)
	}
	if !strings.HasSuffix(rendered, "/24") {
		t.Errorf("the prefix length was lost, which is what says how wide the route is: %s", rendered)
	}
}
