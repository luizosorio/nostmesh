package observability

// Reason codes classify why something failed or was refused.
//
// The vocabulary is closed on purpose. A reason built from an error's text
// cannot be counted or alerted on, and — because most refusals originate in
// something a peer sent — interpolating one is also how peer-controlled content
// reaches a log. The protocol documentation is explicit that rejected content is
// never logged in full; a code is what replaces it.
//
// Adding a code here is the review prompt for adding a new failure mode.

// Control plane: relays, envelopes and their validation.
const (
	// ReasonRelayUnreachable is a relay that could not be dialled.
	ReasonRelayUnreachable = "relay_unreachable"

	// ReasonRelayClosed is a relay that closed the connection or subscription.
	ReasonRelayClosed = "relay_closed"

	// ReasonRelayRejected is a relay that refused to accept an event.
	ReasonRelayRejected = "relay_rejected"

	// ReasonMalformed is an envelope that did not parse or failed structural
	// validation.
	ReasonMalformed = "malformed"

	// ReasonOversized is an envelope or payload beyond the protocol's limits.
	ReasonOversized = "oversized"

	// ReasonUnsupportedVersion is a protocol version this build does not speak.
	ReasonUnsupportedVersion = "unsupported_version"

	// ReasonWrongRecipient is a message addressed to another node.
	ReasonWrongRecipient = "wrong_recipient"

	// ReasonBadSignature is an envelope whose signature did not verify.
	ReasonBadSignature = "bad_signature"

	// ReasonDecryptFailed is a payload that would not decrypt.
	//
	// Deliberately undifferentiated from a malformed ciphertext: telling the two
	// apart would answer a question an attacker is asking.
	ReasonDecryptFailed = "decrypt_failed"

	// ReasonExpired is a message outside its validity window.
	ReasonExpired = "expired"

	// ReasonReplay is a message already seen, or a sequence already used.
	ReasonReplay = "replay"

	// ReasonDuplicate is a copy of a message already processed, which is
	// ordinary with several relays rather than an attack.
	ReasonDuplicate = "duplicate"

	// ReasonUnknownSession is a message for a session this node does not hold.
	ReasonUnknownSession = "unknown_session"

	// ReasonOutOfOrder is a message that does not fit the session's state.
	ReasonOutOfOrder = "out_of_order"
)

// Policy: what this node will and will not agree to.
const (
	// ReasonUnauthorized is a peer absent from the allowlist, or revoked.
	ReasonUnauthorized = "unauthorized"

	// ReasonNoAllowedIPs is an authorized peer with nothing configured to route,
	// which is a tunnel that would carry nothing.
	ReasonNoAllowedIPs = "no_allowed_ips"

	// ReasonPolicyRefused is a proposal local policy declined.
	ReasonPolicyRefused = "policy_refused"
)

// Connectivity: candidates, probes and path selection.
const (
	// ReasonNoCandidates is a gather that produced nothing usable.
	// ReasonSameIdentity reports a peer presenting this node's own identity.
	//
	// Not a failure of the peer or the path: it is a configuration that cannot
	// work, and the operator who created it is the only one who can undo it.
	ReasonSameIdentity = "same_identity"

	// ReasonSingleObserver reports a node that cannot compare observations.
	//
	// Not a failure: the node works. It says the node has no way to notice that
	// its public address changed between sessions, because there is only one
	// answer and nothing to check it against.
	ReasonSingleObserver = "single_observer"

	ReasonNoCandidates = "no_candidates"

	// ReasonProbeTimeout is a connectivity check that got no answer.
	ReasonProbeTimeout = "probe_timeout"

	// ReasonProbeUnauthenticated is a probe response that did not authenticate,
	// which is either the wrong peer or a forgery.
	ReasonProbeUnauthenticated = "probe_unauthenticated"

	// ReasonObserverUnreachable is a STUN observer that did not answer.
	ReasonObserverUnreachable = "observer_unreachable"

	// ReasonNoPath is every candidate pair having failed.
	ReasonNoPath = "no_path"
)

// Data plane: the kernel, the tunnel and the network journal.
const (
	// ReasonHandshakeStale is a tunnel whose handshake stopped refreshing.
	ReasonHandshakeStale = "handshake_stale"

	// ReasonInterfaceGone is an interface that vanished under a live session.
	ReasonInterfaceGone = "interface_gone"

	// ReasonPeerGone is a peer no longer configured on the interface.
	ReasonPeerGone = "peer_gone"

	// ReasonNotOwned is an interface NostMesh did not create, which it must
	// never modify or remove.
	ReasonNotOwned = "not_owned"

	// ReasonKernelRefused is a netlink operation the kernel rejected.
	ReasonKernelRefused = "kernel_refused"

	// ReasonRoamRejected is an observed endpoint change that was not recorded,
	// most often because the hysteresis window has not elapsed.
	ReasonRoamRejected = "roam_rejected"

	// ReasonRolledBack is a transaction compensated after a failure.
	ReasonRolledBack = "rolled_back"
)

// Lifecycle and local faults.
const (
	// ReasonShutdown is the node stopping deliberately.
	ReasonShutdown = "shutdown"

	// ReasonCancelled is work abandoned because its caller went away.
	ReasonCancelled = "cancelled"

	// ReasonTimeout is a bounded wait that ended empty.
	ReasonTimeout = "timeout"

	// ReasonConfigInvalid is configuration that failed validation.
	ReasonConfigInvalid = "config_invalid"

	// ReasonIOFailed is a local read or write that failed.
	ReasonIOFailed = "io_failed"

	// ReasonInternal is a fault with no better classification. A log full of
	// these is a sign the vocabulary needs extending, not that the code is
	// unknowable.
	ReasonInternal = "internal"
)
