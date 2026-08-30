package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
)

// Error is a single validation failure.
//
// It names the offending field and states what is required, so the message is
// actionable without reading the source.
type Error struct {
	Field   string
	Problem string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Problem)
}

// Errors is an ordered collection of validation failures.
//
// Validation reports every problem it finds rather than stopping at the first,
// so a malformed file can be fixed in one pass.
type Errors []Error

func (e Errors) Error() string {
	if len(e) == 1 {
		return "invalid configuration: " + e[0].Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration: %d problems found:", len(e))
	for _, err := range e {
		b.WriteString("\n  - ")
		b.WriteString(err.Error())
	}
	return b.String()
}

const (
	wireGuardKeyLen = 32
	maxSessionsCap  = 10000
)

var (
	validLogLevels  = []string{"debug", "info", "warn", "error"}
	validLogFormats = []string{"json", "text"}
)

// Validate checks the configuration and returns every problem found.
//
// A nil return means the configuration is structurally sound and its declared
// values are within policy. It does not mean the node will connect: reachability
// is measured, never assumed.
func (c Config) Validate() error {
	var errs Errors

	errs = append(errs, c.Node.validate()...)
	errs = append(errs, c.Log.validate()...)
	errs = append(errs, c.Policy.validate()...)
	errs = append(errs, validatePeers(c.Peers)...)

	if len(errs) == 0 {
		return nil
	}
	return errs
}

func (n Node) validate() Errors {
	var errs Errors

	if n.Name == "" {
		errs = append(errs, Error{"node.name", "must not be empty; set a label for this node"})
	} else if len(n.Name) > 64 {
		errs = append(errs, Error{"node.name", "must be at most 64 characters"})
	}

	switch {
	case n.StateDir == "":
		errs = append(errs, Error{"node.state_dir", "must not be empty; set an absolute path for local state"})
	case !filepath.IsAbs(n.StateDir):
		errs = append(errs, Error{"node.state_dir", fmt.Sprintf("must be an absolute path, got %q", n.StateDir)})
	}

	if n.OverlayAddress != "" {
		if _, err := netip.ParsePrefix(n.OverlayAddress); err != nil {
			errs = append(errs, Error{"node.overlay_address", fmt.Sprintf("must be an address in CIDR notation, got %q", n.OverlayAddress)})
		}
	}

	if n.ListenPort < 0 || n.ListenPort > 65535 {
		errs = append(errs, Error{"node.listen_port", fmt.Sprintf("must be between 0 and 65535, got %d", n.ListenPort)})
	}

	// Below the IPv6 minimum an interface cannot carry a conforming packet;
	// above 1500 it would exceed a standard Ethernet path and fragment.
	if n.MTU != 0 && (n.MTU < 1280 || n.MTU > 1500) {
		errs = append(errs, Error{"node.mtu", fmt.Sprintf("must be between 1280 and 1500, got %d", n.MTU)})
	}

	return errs
}

func (l Log) validate() Errors {
	var errs Errors

	if !slices.Contains(validLogLevels, l.Level) {
		errs = append(errs, Error{"log.level", fmt.Sprintf("must be one of %s, got %q", strings.Join(validLogLevels, ", "), l.Level)})
	}
	if !slices.Contains(validLogFormats, l.Format) {
		errs = append(errs, Error{"log.format", fmt.Sprintf("must be one of %s, got %q", strings.Join(validLogFormats, ", "), l.Format)})
	}

	return errs
}

func (p Policy) validate() Errors {
	var errs Errors

	// Only deny-by-default is accepted. The field is explicit so that an audit
	// can see the stance, not so that it can be relaxed.
	if p.DefaultAction != "deny" {
		errs = append(errs, Error{"policy.default_action", fmt.Sprintf(`must be "deny"; allow-by-default is not supported, got %q`, p.DefaultAction)})
	}

	switch {
	case p.MaxSessions <= 0:
		errs = append(errs, Error{"policy.max_sessions", fmt.Sprintf("must be greater than zero, got %d", p.MaxSessions)})
	case p.MaxSessions > maxSessionsCap:
		errs = append(errs, Error{"policy.max_sessions", fmt.Sprintf("must be at most %d, got %d", maxSessionsCap, p.MaxSessions)})
	}

	return errs
}

func validatePeers(peers []Peer) Errors {
	var errs Errors

	seenNames := make(map[string]int, len(peers))
	seenKeys := make(map[string]int, len(peers))

	for i, peer := range peers {
		field := func(name string) string {
			return fmt.Sprintf("peers[%d].%s", i, name)
		}

		if peer.Name == "" {
			errs = append(errs, Error{field("name"), "must not be empty; set a local label for this peer"})
		} else if first, dup := seenNames[peer.Name]; dup {
			errs = append(errs, Error{field("name"), fmt.Sprintf("duplicates peers[%d].name %q; names must be unique", first, peer.Name)})
		} else {
			seenNames[peer.Name] = i
		}

		errs = append(errs, validatePeerKey(peer.PublicKey, field("public_key"), seenKeys, i)...)
		errs = append(errs, validatePeerEndpoint(peer.Endpoint, field("endpoint"))...)
		errs = append(errs, validatePeerOverlay(peer.OverlayAddress, field("overlay_address"))...)
		errs = append(errs, validatePeerAllowedIPs(peer.AllowedIPs, field("allowed_ips"))...)

		if peer.KeepAlive < 0 {
			errs = append(errs, Error{field("keepalive"), fmt.Sprintf("must not be negative, got %s", peer.KeepAlive)})
		}
	}

	return errs
}

func validatePeerKey(key, field string, seen map[string]int, index int) Errors {
	if key == "" {
		return Errors{{field, "must not be empty; set the peer's WireGuard public key"}}
	}

	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return Errors{{field, "must be a base64-encoded WireGuard public key"}}
	}
	if len(raw) != wireGuardKeyLen {
		return Errors{{field, fmt.Sprintf("must decode to %d bytes, got %d", wireGuardKeyLen, len(raw))}}
	}

	if first, dup := seen[key]; dup {
		return Errors{{field, fmt.Sprintf("duplicates peers[%d].public_key; each peer needs a distinct key", first)}}
	}
	seen[key] = index

	return nil
}

func validatePeerEndpoint(endpoint, field string) Errors {
	if endpoint == "" {
		return Errors{{field, "must not be empty; set the peer's transport address as host:port"}}
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return Errors{{field, fmt.Sprintf("must be host:port, got %q", endpoint)}}
	}
	if host == "" {
		return Errors{{field, "must include a host"}}
	}
	if _, err := net.LookupPort("udp", port); err != nil {
		return Errors{{field, fmt.Sprintf("must have a valid UDP port, got %q", port)}}
	}

	return nil
}

func validatePeerOverlay(address, field string) Errors {
	if address == "" {
		return Errors{{field, "must not be empty; set the peer's overlay address in CIDR notation"}}
	}

	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return Errors{{field, fmt.Sprintf("must be an address in CIDR notation, got %q", address)}}
	}
	if !prefix.Addr().IsValid() {
		return Errors{{field, fmt.Sprintf("must be a valid IP address, got %q", address)}}
	}

	return nil
}

func validatePeerAllowedIPs(allowed []string, field string) Errors {
	if len(allowed) == 0 {
		return Errors{{field, "must list at least one prefix; NostMesh derives routing from local policy, not from the peer"}}
	}

	var errs Errors
	for i, entry := range allowed {
		itemField := fmt.Sprintf("%s[%d]", field, i)

		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			errs = append(errs, Error{itemField, fmt.Sprintf("must be a prefix in CIDR notation, got %q", entry)})
			continue
		}

		// A default route reaches every destination, including the tunnel's own
		// transport endpoint. Accepting one here would silently create a routing
		// loop and hand the peer the node's entire traffic. Transit is a
		// negotiated service with explicit consent, introduced in MVP 4.
		if prefix.Bits() == 0 {
			errs = append(errs, Error{itemField, fmt.Sprintf("must not be a default route (%q); default routes require an explicit transit session, not a static peer", entry)})
		}
	}

	return errs
}
