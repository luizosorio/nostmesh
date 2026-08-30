// Package config defines the declarative configuration of a NostMesh node.
//
// Configuration is validated before it can influence any decision. Defaults are
// deliberately restrictive: an empty configuration yields a node that denies
// every peer and installs nothing on the host.
package config

import "time"

// Config is the root of the declarative configuration.
type Config struct {
	// Node identifies this installation for local diagnostics only. It carries
	// no authority and is never used for authorization.
	Node Node `toml:"node" json:"node"`

	// Log controls observability output.
	Log Log `toml:"log" json:"log"`

	// Policy holds local authorization defaults. Nothing here grants access on
	// its own; every decision starts from deny.
	Policy Policy `toml:"policy" json:"policy"`

	// Peers lists manually configured peers. MVP 0 has no discovery, so this is
	// the only way a peer becomes known.
	Peers []Peer `toml:"peers" json:"peers"`
}

// Node holds node-level settings.
type Node struct {
	// Name is a human-readable label used in logs and diagnostics.
	Name string `toml:"name" json:"name"`

	// StateDir is where the local database and network journal live. It must be
	// an absolute path owned by the running user.
	StateDir string `toml:"state_dir" json:"state_dir"`
}

// Log configures structured logging.
type Log struct {
	// Level is one of: debug, info, warn, error.
	Level string `toml:"level" json:"level"`

	// Format is one of: json, text. JSON is the default because logs are meant
	// to be machine-readable.
	Format string `toml:"format" json:"format"`
}

// Policy carries local authorization settings.
//
// The zero value denies everything. There is no configuration that turns the
// node into an open relay by accident.
type Policy struct {
	// DefaultAction applies when no rule matches. Only "deny" is accepted;
	// the field exists to make the default explicit and auditable, not to
	// offer an allow-by-default mode.
	DefaultAction string `toml:"default_action" json:"default_action"`

	// AcceptDefaultRoute must be explicitly enabled before the node will even
	// consider a 0.0.0.0/0 or ::/0 announcement. Enabling it does not accept
	// such a route; it only makes the route eligible for confirmation.
	AcceptDefaultRoute bool `toml:"accept_default_route" json:"accept_default_route"`

	// MaxSessions caps concurrent sessions.
	MaxSessions int `toml:"max_sessions" json:"max_sessions"`
}

// Peer is a manually configured WireGuard peer.
//
// Every field here is local intent. Nothing in a Peer comes from the network,
// and no remote party can add or modify one.
type Peer struct {
	// Name is a local label for the peer.
	Name string `toml:"name" json:"name"`

	// PublicKey is the peer's WireGuard public key, base64-encoded.
	PublicKey string `toml:"public_key" json:"public_key"`

	// Endpoint is the peer's transport address as host:port.
	Endpoint string `toml:"endpoint" json:"endpoint"`

	// OverlayAddress is the address assigned to the peer inside the tunnel,
	// in CIDR notation.
	OverlayAddress string `toml:"overlay_address" json:"overlay_address"`

	// AllowedIPs lists the prefixes routed to this peer. These are derived from
	// local policy and never accepted from the peer itself.
	AllowedIPs []string `toml:"allowed_ips" json:"allowed_ips"`

	// KeepAlive is the persistent keepalive interval. Zero disables it.
	KeepAlive time.Duration `toml:"keepalive" json:"keepalive"`
}

// Default returns a configuration with safe defaults applied.
//
// The result is intentionally not usable as-is: it denies every peer and has no
// state directory. Callers must supply the missing values.
func Default() Config {
	return Config{
		Log: Log{
			Level:  "info",
			Format: "json",
		},
		Policy: Policy{
			DefaultAction:      "deny",
			AcceptDefaultRoute: false,
			MaxSessions:        64,
		},
	}
}
