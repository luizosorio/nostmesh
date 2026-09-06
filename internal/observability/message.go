package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/luizosorio/nostmesh/internal/protocol"
)

// EnvelopeAttrs renders a control message's routing metadata.
//
// Every field here was already visible to every relay that carried the event, so
// recording it discloses nothing the transport did not. Body is the exception
// and is never rendered: it is the ciphertext, which the operations
// documentation forbids outright.
//
// It implements slog.LogValuer, so none of this work happens unless the record
// is actually going to be emitted.
type EnvelopeAttrs struct {
	Envelope protocol.Envelope
	Mode     Diagnostic
}

// LogValue renders the envelope.
func (e EnvelopeAttrs) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.Int("v", e.Envelope.Version),
		slog.String("type", string(e.Envelope.Type)),
		slog.String("message_id", Abbreviate(e.Envelope.MessageID)),
		slog.String("session", Abbreviate(e.Envelope.SessionID)),
		slog.Uint64("seq", e.Envelope.Seq),
		slog.Int64("created_at", e.Envelope.CreatedAt),
		slog.Int64("expires_at", e.Envelope.ExpiresAt),
		slog.String("sender", Abbreviate(e.Envelope.Sender)),
		slog.String("recipient", Abbreviate(e.Envelope.Recipient)),

		// The ciphertext is described, never carried. Its length bounds what was
		// exchanged, and the digest is what lets the same message be recognised
		// on both hosts — message_id is chosen by the sender and does not prove
		// the bodies matched.
		slog.Int("body_len", len(e.Envelope.Body)),
		slog.String("body_digest", digestOf(e.Envelope.Body)),
	}

	if e.Envelope.ReplyTo != "" {
		attrs = append(attrs, slog.String("reply_to", Abbreviate(e.Envelope.ReplyTo)))
	}
	if len(e.Envelope.Critical) > 0 {
		attrs = append(attrs, slog.Any("critical", e.Envelope.Critical))
	}

	// The namespace is constant for every message this build produces, so it
	// earns its place only when it is not the expected one — at which point it
	// is the whole explanation for a rejection.
	if e.Envelope.Namespace != protocol.Namespace {
		attrs = append(attrs, slog.String("namespace", e.Envelope.Namespace))
	}

	return slog.GroupValue(attrs...)
}

// NegotiationAttrs renders a decrypted control message.
//
// This is the plaintext of the control plane, not traffic content: it is what
// the two nodes are agreeing on, and an operator who cannot see it cannot
// diagnose a handshake that stalls. The private key never appears here because
// it is never transmitted — only the WireGuard *public* key is exchanged.
//
// Addresses inside it are subject to the gate, because a candidate list is
// where a private address would otherwise reach a log.
type NegotiationAttrs struct {
	Payload protocol.Payload
	Mode    Diagnostic
}

// LogValue renders whichever message the payload carries.
func (n NegotiationAttrs) LogValue() slog.Value {
	switch {
	case n.Payload.Request != nil:
		return slog.GroupValue(
			slog.String("kind", "request"),
			slog.String("tunnel_key", Abbreviate(n.Payload.Request.TunnelKey.PublicKey)),
			slog.Int64("key_expires_at", n.Payload.Request.TunnelKey.ExpiresAt),
			slog.Attr{Key: "capabilities", Value: capabilityAttrs(n.Payload.Request.Capabilities)},
			overlayAttr(n.Payload.Request.OverlayAddress, n.Mode),
		)

	case n.Payload.Offer != nil:
		return slog.GroupValue(
			slog.String("kind", "offer"),
			slog.String("tunnel_key", Abbreviate(n.Payload.Offer.TunnelKey.PublicKey)),
			slog.Int64("key_expires_at", n.Payload.Offer.TunnelKey.ExpiresAt),
			slog.Int("agreed_version", n.Payload.Offer.AgreedVersion),
			slog.Any("agreed_transports", n.Payload.Offer.AgreedTransports),
			overlayAttr(n.Payload.Offer.OverlayAddress, n.Mode),
		)

	case n.Payload.Accept != nil:
		return slog.GroupValue(
			slog.String("kind", "accept"),
			// The offer hash is what binds an acceptance to exact terms, so a
			// mismatch between the two ends is the whole diagnosis.
			slog.String("offer_hash", Abbreviate(n.Payload.Accept.OfferHash)),
		)

	case n.Payload.Candidate != nil:
		return slog.GroupValue(
			slog.String("kind", "candidate"),
			slog.Int("added", len(n.Payload.Candidate.Added)),
			slog.Int("removed", len(n.Payload.Candidate.Removed)),
			slog.Bool("final", n.Payload.Candidate.Final),
			slog.Any("candidates", candidateAttrs(n.Payload.Candidate.Added, n.Mode)),
		)

	case n.Payload.Ready != nil:
		return slog.GroupValue(
			slog.String("kind", "ready"),
			slog.String("selected_candidate", n.Payload.Ready.SelectedCandidate),
		)

	case n.Payload.Keepalive != nil:
		return slog.GroupValue(
			slog.String("kind", "keepalive"),
			slog.Uint64("sequence", n.Payload.Keepalive.Sequence),
		)

	case n.Payload.Close != nil:
		return slog.GroupValue(
			slog.String("kind", "close"),
			slog.String("reason", string(n.Payload.Close.Reason)),
		)

	case n.Payload.Error != nil:
		return slog.GroupValue(
			slog.String("kind", "error"),
			slog.String("code", string(n.Payload.Error.Code)),
		)
	}

	return slog.GroupValue(slog.String("kind", "empty"))
}

// capabilityAttrs renders what a node declared it supports.
//
// A group value, so the fields nest under one key. Unlike a slice of values, a
// group returned from LogValue is resolved by the handler.
func capabilityAttrs(capabilities protocol.Capabilities) slog.Value {
	attrs := []slog.Attr{
		slog.Any("protocol_versions", capabilities.ProtocolVersions),
		slog.Any("transports", capabilities.Transports),
		slog.Any("candidate_types", capabilities.CandidateTypes),
	}
	if len(capabilities.Extensions) > 0 {
		attrs = append(attrs, slog.Any("extensions", capabilities.Extensions))
	}
	return slog.GroupValue(attrs...)
}

// candidateAttrs renders the candidates a peer offered.
//
// This is the single most useful thing at debug when a session will not
// establish, and the single most sensitive: a candidate list describes the
// peer's networks. Addresses go through the gate; everything else — kind,
// priority, identity — is structure and is always shown.
func candidateAttrs(candidates []protocol.Candidate, mode Diagnostic) []string {
	rendered := make([]string, 0, len(candidates))

	for _, candidate := range candidates {
		// Rendered as one string per candidate rather than as a group.
		//
		// A slog.Value inside a slice is not resolved by the JSON handler — it
		// marshals as an empty object, which is how the single most useful field
		// at debug silently became "[{},{}]". A list of candidates is read as a
		// list, so it is written as one.
		line := candidate.ID + " " + string(candidate.Type) + "/" + candidate.Transport +
			" " + renderCandidateAddress(candidate.Address, mode) +
			" priority=" + strconv.FormatUint(uint64(candidate.Priority), 10)

		if candidate.RelatedAddress != "" {
			line += " related=" + renderCandidateAddress(candidate.RelatedAddress, mode)
		}
		rendered = append(rendered, line)
	}

	return rendered
}

// renderCandidateAddress applies the gate to an address that arrived as text.
//
// A candidate's address comes from a peer, so it may not parse. An unparseable
// value is reported as such rather than echoed: it came from outside, and
// echoing it verbatim is how peer-controlled content reaches a log.
func renderCandidateAddress(address string, mode Diagnostic) string {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil {
		return addrInvalid
	}
	return renderAddrPort(parsed, mode)
}

// overlayAttr renders a proposed overlay address.
//
// The field is a proposal: what this node installs comes from local policy. It
// is logged so that a mismatch between what a peer asked for and what was
// configured is visible, which is otherwise invisible from either side.
func overlayAttr(address string, mode Diagnostic) slog.Attr {
	if address == "" {
		return slog.String("overlay_address", "")
	}

	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return slog.String("overlay_address", addrInvalid)
	}
	return slog.String("overlay_address", renderPrefix(prefix, mode))
}

// digestOf identifies a ciphertext without carrying it.
func digestOf(body string) string {
	if body == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])[:idPrefix]
}
