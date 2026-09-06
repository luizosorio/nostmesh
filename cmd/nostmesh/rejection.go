package main

import (
	"errors"

	"github.com/luizosorio/nostmesh/internal/nostr"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// classifyRejection maps a refusal to a reason code.
//
// A refused message is one a peer sent, so its error text is derived from
// attacker-controllable input: the protocol documentation requires that rejected
// content never reach a log in full, and interpolating the error is how it would.
// A code says the same thing to an operator, can be counted, and carries nothing
// from outside.
//
// Matching is on the sentinel errors rather than on message text. Comparing
// strings would silently stop classifying the first time a message was reworded,
// and the failure mode is a log that says "internal" about something it knows.
func classifyRejection(err error) string {
	switch {
	case err == nil:
		return ""

	// Structure and limits, checked before anything expensive happens.
	case errors.Is(err, protocol.ErrTooLarge):
		return observability.ReasonOversized
	case errors.Is(err, protocol.ErrMalformed):
		return observability.ReasonMalformed
	case errors.Is(err, protocol.ErrUnsupportedVersion):
		return observability.ReasonUnsupportedVersion
	case errors.Is(err, protocol.ErrUnknownNamespace), errors.Is(err, protocol.ErrUnknownType):
		return observability.ReasonMalformed
	case errors.Is(err, protocol.ErrCriticalExtension):
		return observability.ReasonUnsupportedVersion

	// Addressing and validity.
	case errors.Is(err, protocol.ErrWrongRecipient):
		return observability.ReasonWrongRecipient
	case errors.Is(err, protocol.ErrExpired), errors.Is(err, protocol.ErrNotYetValid):
		return observability.ReasonExpired

	// Authorship.
	case errors.Is(err, nostr.ErrInvalidSignature):
		return observability.ReasonBadSignature
	case errors.Is(err, errNotFromPeer), errors.Is(err, errSenderMismatch):
		return observability.ReasonWrongRecipient

	// Session binding.
	case errors.Is(err, errWrongSession):
		return observability.ReasonUnknownSession
	}

	// Deliberately not a fallback that echoes the error. A message this does not
	// recognise still gets a code; the error itself stays out of the record, and
	// a log filling with this one is the prompt to extend the vocabulary rather
	// than to start interpolating.
	return observability.ReasonMalformed
}
