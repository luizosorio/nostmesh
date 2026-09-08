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

	// Network configures derived addressing. Optional: a node without it keeps
	// using the manually chosen node.overlay_address, which is what every
	// deployment before this did and must keep doing.
	Network Network `toml:"network" json:"network,omitempty"`

	// Routes configures what this node announces to its peers.
	Routes Routes `toml:"routes" json:"routes,omitempty"`
}

// Routes says which private prefixes this node offers to reach.
//
// Empty by default: a node announces nothing unless its operator says it can
// reach something. What a peer does with an announcement is entirely that
// peer's decision — this is a claim, never an instruction (NM-25).
type Routes struct {
	// Advertise lists the prefixes this node offers to route.
	//
	// Local intent. The operator is stating what this host can actually reach,
	// and getting it wrong announces a destination that black-holes rather than
	// one that is refused, so it is deliberately not derived from the host's
	// interfaces: a node that announced whatever it happened to see would offer
	// its own LAN to strangers by default.
	Advertise []string `toml:"advertise" json:"advertise,omitempty"`

	// Metric is what this node claims about its own cost to those prefixes.
	//
	// A claim about itself, which the receiver treats as one input among
	// several. Zero takes a default rather than meaning "free".
	Metric uint32 `toml:"metric" json:"metric,omitempty"`
}

// Network configures a node's membership of an overlay network.
//
// It is optional and off by default. Setting it makes this node derive its
// address from the manifest rather than take one from node.overlay_address, per
// NM-21 — but nothing about it changes what a node without it does.
type Network struct {
	// Manifest is the path to the signed manifest describing the network.
	//
	// A file rather than a relay subscription for now: the manifest's transport
	// is a separate delivery, and reading one from disk is what makes the rest
	// of this testable and deployable in the meantime.
	Manifest string `toml:"manifest" json:"manifest,omitempty"`

	// Issuer is the Nostr public key this node pins as the manifest's author,
	// hex-encoded.
	//
	// The pin is what makes a manifest local intent rather than remote
	// authority: a manifest signed by anyone else is not this network's,
	// whatever it claims inside. There is no default, and an absent one means
	// no manifest is accepted at all.
	Issuer string `toml:"issuer" json:"issuer,omitempty"`

	// Salt is the network's shared secret, hex-encoded.
	//
	// It never appears in the manifest and is distributed out of band, which is
	// what stops a relay operator holding every published event from deriving a
	// single member's address. Treat it as a secret: a node's configuration file
	// is already 0600 for the same reason.
	Salt string `toml:"salt" json:"salt,omitempty"`

	// Subnet selects which of the manifest's subnets this node uses. Zero is
	// the first, which is what a network that never carved one wants.
	Subnet int `toml:"subnet" json:"subnet,omitempty"`
}

// Enabled reports whether derived addressing is configured.
//
// All three of manifest, issuer and salt are needed: a manifest without an
// issuer cannot be trusted, and one without a salt cannot derive anything.
// Partial configuration is a mistake rather than a mode, and validation says so.
func (n Network) Enabled() bool {
	return n.Manifest != "" || n.Issuer != "" || n.Salt != ""
}

// Node holds node-level settings.
type Node struct {
	// Name is a human-readable label used in logs and diagnostics.
	Name string `toml:"name" json:"name"`

	// StateDir is where the local database and network journal live. It must be
	// an absolute path owned by the running user.
	StateDir string `toml:"state_dir" json:"state_dir"`

	// OverlayAddress is this node's own address inside the tunnel, in CIDR
	// notation. It is local intent, never negotiated.
	OverlayAddress string `toml:"overlay_address" json:"overlay_address"`

	// ListenPort is the UDP port WireGuard binds. Zero lets the kernel choose,
	// which is fine for a client but not for a node peers dial into.
	ListenPort int `toml:"listen_port" json:"listen_port"`

	// MTU is the tunnel interface MTU. Zero uses the adapter default of 1420,
	// which leaves room for the WireGuard header inside a 1500-byte path.
	MTU int `toml:"mtu" json:"mtu"`

	// Relays are the Nostr relays used for signalling. Three or more is
	// recommended: relays are untrusted for availability, and redundancy is
	// what keeps one going down from stopping the control plane.
	//
	// They never carry user traffic. That goes over WireGuard.
	Relays []string `toml:"relays" json:"relays,omitempty"`

	// Observers are STUN servers used to discover this node's mapped address,
	// consulted only when local discovery finds nothing routable.
	Observers []string `toml:"observers" json:"observers,omitempty"`
}

// Log configures structured logging.
type Log struct {
	// Level is one of: debug, info, warn, error.
	Level string `toml:"level" json:"level"`

	// Format is one of: json, text. JSON is the default because logs are meant
	// to be machine-readable.
	Format string `toml:"format" json:"format"`

	// File is an optional second sink, in addition to the system log.
	//
	// Logs always reach the system log through the supervisor. This adds a copy
	// on disk for an operator who wants one that outlives the journal's
	// retention or who runs without a supervisor at all.
	//
	// It must be absolute: a relative path would resolve against whatever
	// directory the service happened to start in, which is not a property
	// anyone should have to reason about when looking for their logs.
	File string `toml:"file" json:"file,omitempty"`

	// Diagnostic is the explicit opt-in before addresses are written in full.
	//
	// One of: "off" (the default), "addresses". It is deliberately not a log
	// level: raising verbosity to work out why a handshake stalls is routine,
	// and consenting to write peer addresses to disk is not. Collapsing the two
	// would make the second happen by accident every time somebody did the
	// first.
	//
	// Only settable here, never by flag or environment variable. Editing a
	// root-owned file is the friction that makes the choice deliberate.
	Diagnostic string `toml:"diagnostic" json:"diagnostic,omitempty"`
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

	// AuthorizedPeers is the allowlist. It is empty by default, which means
	// nobody is authorized: a valid signature proves who is asking, not that
	// they may.
	AuthorizedPeers []AuthorizedPeer `toml:"authorized_peers" json:"authorized_peers,omitempty"`

	// Groups authorize several identities with one rule.
	//
	// A rule per pubkey is right when each peer is a separate judgement. For a
	// set of devices that are all trusted the same way it is ceremony: the tenth
	// rule carries no more intent than the first, and the repetition is where an
	// operator makes a mistake.
	//
	// This does not relax the default. A group is a shorter way to say who is
	// trusted, never a way to skip saying it, and a peer no group names is still
	// refused. See NM-24.
	Groups []PolicyGroup `toml:"groups" json:"groups,omitempty"`
}

// PolicyGroup authorizes every identity it names.
//
// Members are listed here rather than taken from a network manifest. NM-24
// describes a group as a manifest's membership, which is the direction, but the
// manifest is not yet wired into the service — so today the operator writes the
// members and the rule tracks exactly what they wrote.
type PolicyGroup struct {
	// Name identifies the group in a rule and in an explanation. It is a local
	// label and carries no authority, like an alias.
	Name string `toml:"name" json:"name"`

	// Members are the Nostr identities the rule covers, hex-encoded.
	Members []string `toml:"members" json:"members"`

	// Actions lists what members may do: session, route, transit.
	Actions []string `toml:"actions" json:"actions"`

	// AllowedIPs lists the prefixes this node will accept from a member.
	//
	// Local intent, exactly as in AuthorizedPeer: the same prefixes for everyone
	// the group covers.
	AllowedIPs []string `toml:"allowed_ips" json:"allowed_ips,omitempty"`
}

// AuthorizedPeer grants a peer permission to act.
type AuthorizedPeer struct {
	// PublicKey is the peer's Nostr identity, hex-encoded.
	PublicKey string `toml:"public_key" json:"public_key"`

	// Alias is a local label with no authority.
	Alias string `toml:"alias" json:"alias,omitempty"`

	// Actions lists what the peer may do: session, route, transit. An action
	// absent from the list is refused.
	Actions []string `toml:"actions" json:"actions"`

	// AllowedIPs lists the prefixes this node will accept from the peer through
	// a negotiated tunnel.
	//
	// It belongs here rather than under [[peers]] because a negotiated session's
	// tunnel key is ephemeral and unknown in advance, so the only stable way to
	// name the far side is its Nostr identity. Like every other AllowedIPs in
	// this configuration it is local intent: a peer asking to route a prefix is
	// making a request, and this is the answer, decided ahead of time.
	AllowedIPs []string `toml:"allowed_ips" json:"allowed_ips,omitempty"`

	// Revoked withdraws the grant while keeping the record, so an operator can
	// see a peer was deliberately removed rather than never added.
	Revoked bool `toml:"revoked" json:"revoked,omitempty"`
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
