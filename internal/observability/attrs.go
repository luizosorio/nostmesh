package observability

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// Attribute keys, so a filter is written against a constant rather than a
// string spelled two ways in two places.
const (
	KeyEvent      = "event"
	KeyResult     = "result"
	KeyReason     = "reason_code"
	KeyDuration   = "duration_ms"
	KeyNode       = "node"
	KeyPeer       = "peer"
	KeyTunnelKey  = "tunnel_key"
	KeySession    = "session"
	KeyEndpoint   = "endpoint"
	KeyAllowedIPs = "allowed_ips"
	KeyDiagnostic = "diagnostic"
)

// Results, the outcome of whatever the event describes.
const (
	ResultOK       = "ok"
	ResultRefused  = "refused"
	ResultFailed   = "failed"
	ResultTimeout  = "timeout"
	ResultDegraded = "degraded"
)

// idPrefix is how much of an identifier a log line carries.
//
// Enough to correlate lines within a session, and not enough to serve as a
// durable handle for the identity behind it. The operations documentation asks
// for `node_id` abbreviated for the same reason.
const idPrefix = 8

// Event names what happened.
//
// Every line carries one. It is the field a filter selects on, so it is a
// closed vocabulary rather than a sentence: the message is for a human, the
// event is for a query.
func Event(name string) slog.Attr { return slog.String(KeyEvent, name) }

// Result reports how the event turned out.
func Result(result string) slog.Attr { return slog.String(KeyResult, result) }

// Reason carries a classified cause.
//
// It takes a constant from reasons.go, never an error's text. A free-form
// message cannot be aggregated, and — since most causes originate in something a
// peer sent — it is also the way peer-controlled content reaches a log. Where
// the message itself is safe and useful, it goes in a separate error attribute.
func Reason(code string) slog.Attr { return slog.String(KeyReason, code) }

// Duration reports elapsed time in milliseconds.
func Duration(d time.Duration) slog.Attr {
	return slog.Int64(KeyDuration, d.Milliseconds())
}

// Node identifies this node, abbreviated.
func Node(key domain.NostrPublicKey) slog.Attr {
	return slog.String(KeyNode, shortNostr(key))
}

// Peer identifies the far side, abbreviated.
func Peer(key domain.NostrPublicKey) slog.Attr {
	return slog.String(KeyPeer, shortNostr(key))
}

// TunnelKey identifies a WireGuard peer by its public key, abbreviated.
//
// The public key is not a secret — it is exchanged in the clear inside the
// encrypted payload and the kernel reports it to anyone who can read the
// interface. It is abbreviated for the same reason an identity is: a full key is
// a durable handle, and a log does not need to be one.
func TunnelKey(key domain.WireGuardPublicKey) slog.Attr {
	return slog.String(KeyTunnelKey, shortWireGuard(key))
}

// Session identifies a session, abbreviated.
func Session(id string) slog.Attr {
	return slog.String(KeySession, Abbreviate(id))
}

// Endpoint records where a tunnel reaches a peer, subject to the gate.
func Endpoint(addr netip.AddrPort, mode Diagnostic) slog.Attr {
	return slog.String(KeyEndpoint, renderAddrPort(addr, mode))
}

// AllowedIPs records what a peer is routed, subject to the gate.
func AllowedIPs(prefixes []netip.Prefix, mode Diagnostic) slog.Attr {
	rendered := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		rendered = append(rendered, renderPrefix(prefix, mode))
	}
	return slog.Any(KeyAllowedIPs, rendered)
}

// Abbreviate shortens an identifier to its logging prefix.
//
// Exported because session identifiers arrive as strings from several places
// and every one of them must shorten the same way; two different prefixes for
// the same session would make the lines impossible to join.
func Abbreviate(id string) string {
	if len(id) <= idPrefix {
		return id
	}
	return id[:idPrefix]
}

// shortNostr abbreviates a Nostr public key, tolerating the zero value.
//
// A zero key means "not known yet", which happens legitimately before a peer is
// identified. Rendering it as eight zeros would look like an identity.
func shortNostr(key domain.NostrPublicKey) string {
	if key.IsZero() {
		return ""
	}
	return key.Short()
}

// shortWireGuard abbreviates a WireGuard public key, tolerating the zero value.
func shortWireGuard(key domain.WireGuardPublicKey) string {
	if key.IsZero() {
		return ""
	}
	return key.Short()
}
