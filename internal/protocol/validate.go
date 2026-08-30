package protocol

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// supportedExtensions lists critical extensions this build can honour.
//
// Empty for now: this version defines no extensions. A message marking any
// extension critical is therefore refused, which is the correct behaviour —
// the sender said it was essential.
var supportedExtensions = []string{}

// ValidateEnvelope checks an envelope in cheapest-first order.
//
// The ordering is a defence, not a style preference. Each step is more
// expensive than the last, and an attacker who can make us decrypt garbage
// costs us far more than one who can make us compare two integers. Signature
// verification and decryption happen only after everything cheap has passed.
//
// This function covers steps 1 through 5 of the documented validation order.
// Signature checking, rate limiting and decryption belong to the transport, and
// policy evaluation to the orchestrator.
func ValidateEnvelope(e Envelope, localNode string, now time.Time) error {
	// 1. Version and namespace: a single integer and string comparison.
	if e.Version != Version {
		return fmt.Errorf("%w: %d, this build speaks %d", ErrUnsupportedVersion, e.Version, Version)
	}
	if e.Namespace != Namespace {
		return fmt.Errorf("%w: %q", ErrUnknownNamespace, e.Namespace)
	}

	// 2. Type: a map lookup.
	if !e.Type.IsKnown() {
		return fmt.Errorf("%w: %q", ErrUnknownType, e.Type)
	}

	// 3. Critical extensions: refuse before doing any work the sender considers
	// meaningless without them.
	if err := validateCritical(e.Critical); err != nil {
		return err
	}

	// 4. Structure: field shapes and sizes.
	if err := validateFields(e); err != nil {
		return err
	}

	// 5. Recipient and validity window.
	if localNode != "" && e.Recipient != localNode {
		return fmt.Errorf("%w: addressed to %s", ErrWrongRecipient, abbreviate(e.Recipient))
	}
	return validateWindow(e, now)
}

func validateCritical(extensions []string) error {
	if len(extensions) > MaxCriticalExtensions {
		return fmt.Errorf("%w: %d critical extensions, limit is %d",
			ErrTooLarge, len(extensions), MaxCriticalExtensions)
	}
	for _, extension := range extensions {
		if !slices.Contains(supportedExtensions, extension) {
			return fmt.Errorf("%w: %q", ErrCriticalExtension, extension)
		}
	}
	return nil
}

func validateFields(e Envelope) error {
	if err := validateHexField("message_id", e.MessageID, 16); err != nil {
		return err
	}
	if err := validateHexField("session_id", e.SessionID, 32); err != nil {
		return err
	}
	if err := validateHexField("sender", e.Sender, 32); err != nil {
		return err
	}
	if err := validateHexField("recipient", e.Recipient, 32); err != nil {
		return err
	}

	if e.Sender == e.Recipient {
		return fmt.Errorf("%w: sender and recipient are identical", ErrMalformed)
	}

	if e.ReplyTo != "" {
		if err := validateHexField("reply_to", e.ReplyTo, 16); err != nil {
			return err
		}
	}

	if e.Body == "" {
		return fmt.Errorf("%w: body is empty", ErrMalformed)
	}
	if len(e.Body) > MaxPayloadSize {
		return fmt.Errorf("%w: body is %d bytes, limit is %d", ErrTooLarge, len(e.Body), MaxPayloadSize)
	}
	if _, err := base64.StdEncoding.DecodeString(e.Body); err != nil {
		return fmt.Errorf("%w: body is not valid base64", ErrMalformed)
	}

	return nil
}

func validateHexField(name, value string, wantBytes int) error {
	if value == "" {
		return fmt.Errorf("%w: %s is empty", ErrMalformed, name)
	}

	raw, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%w: %s is not hex", ErrMalformed, name)
	}
	if len(raw) != wantBytes {
		return fmt.Errorf("%w: %s must be %d bytes, got %d", ErrMalformed, name, wantBytes, len(raw))
	}

	// An all-zero identifier means uninitialized memory reached the wire.
	var acc byte
	for _, b := range raw {
		acc |= b
	}
	if acc == 0 {
		return fmt.Errorf("%w: %s is all zeros", ErrMalformed, name)
	}

	return nil
}

// validateWindow checks the validity window against the local clock.
//
// Remote timestamps are untrusted. They decide only whether a message falls
// inside a window; ordering within a session comes from sequence numbers, which
// cannot be affected by a wrong clock on either side.
func validateWindow(e Envelope, now time.Time) error {
	created := e.CreatedTime()
	expires := e.ExpiryTime()

	if e.CreatedAt <= 0 || e.ExpiresAt <= 0 {
		return fmt.Errorf("%w: timestamps must be positive", ErrMalformed)
	}
	if !expires.After(created) {
		return fmt.Errorf("%w: expires at or before creation", ErrMalformed)
	}
	if expires.Sub(created) > MaxValidity {
		return fmt.Errorf("%w: validity window is %s, limit is %s",
			ErrMalformed, expires.Sub(created), MaxValidity)
	}

	if created.After(now.Add(MaxClockSkew)) {
		return fmt.Errorf("%w: created %s in the future", ErrNotYetValid, created.Sub(now).Round(time.Second))
	}
	if now.After(expires.Add(MaxClockSkew)) {
		return fmt.Errorf("%w: expired %s ago", ErrExpired, now.Sub(expires).Round(time.Second))
	}

	return nil
}

// ValidatePayload checks a decrypted payload against its envelope.
func ValidatePayload(p Payload, e Envelope, now time.Time) error {
	if err := p.MatchesEnvelope(e.Type); err != nil {
		return err
	}

	switch {
	case p.Request != nil:
		return validateRequest(*p.Request, now)
	case p.Offer != nil:
		return validateOffer(*p.Offer, now)
	case p.Accept != nil:
		return validateAccept(*p.Accept)
	case p.Candidate != nil:
		return validateCandidates(*p.Candidate)
	case p.Close != nil:
		return validateClose(*p.Close)
	case p.Error != nil:
		return validateError(*p.Error)
	default:
		// Ready and Keepalive carry nothing that needs checking.
		return nil
	}
}

func validateRequest(r SessionRequest, now time.Time) error {
	if err := validateCapabilities(r.Capabilities); err != nil {
		return err
	}
	return validateTunnelKey(r.TunnelKey, now)
}

func validateOffer(o SessionOffer, now time.Time) error {
	if err := validateCapabilities(o.Capabilities); err != nil {
		return err
	}
	if err := validateTunnelKey(o.TunnelKey, now); err != nil {
		return err
	}

	// The agreed version must be one this build speaks. A peer claiming
	// agreement on a version we never offered is either confused or attempting
	// a downgrade.
	if o.AgreedVersion != Version {
		return fmt.Errorf("%w: offer agrees on version %d, this build speaks %d",
			ErrUnsupportedVersion, o.AgreedVersion, Version)
	}
	if len(o.AgreedTransports) == 0 {
		return fmt.Errorf("%w: offer agrees on no transport", ErrMalformed)
	}

	return nil
}

func validateAccept(a SessionAccept) error {
	raw, err := hex.DecodeString(a.OfferHash)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("%w: offer hash must be a 32-byte hex digest", ErrMalformed)
	}
	return nil
}

func validateCapabilities(c Capabilities) error {
	if len(c.ProtocolVersions) == 0 {
		return fmt.Errorf("%w: capabilities declare no protocol version", ErrMalformed)
	}
	if !slices.Contains(c.ProtocolVersions, Version) {
		return fmt.Errorf("%w: peer speaks %v, this build speaks %d",
			ErrUnsupportedVersion, c.ProtocolVersions, Version)
	}
	if len(c.Transports) == 0 {
		return fmt.Errorf("%w: capabilities declare no transport", ErrMalformed)
	}
	return nil
}

// validateTunnelKey checks the WireGuard public key and its binding.
//
// Only the public key may appear here. A value that decodes to the right length
// is not proof of anything on its own — the authorization comes from the
// binding to session, sender, recipient and expiry, which the envelope's
// associated data authenticates.
func validateTunnelKey(k TunnelKey, now time.Time) error {
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: tunnel key is not base64", ErrMalformed)
	}
	if len(raw) != 32 {
		return fmt.Errorf("%w: tunnel key must be 32 bytes, got %d", ErrMalformed, len(raw))
	}

	var acc byte
	for _, b := range raw {
		acc |= b
	}
	if acc == 0 {
		return fmt.Errorf("%w: tunnel key is all zeros", ErrMalformed)
	}

	if err := validateHexField("tunnel_key.nonce", k.Nonce, 16); err != nil {
		return err
	}

	if k.ExpiresAt <= 0 {
		return fmt.Errorf("%w: tunnel key has no expiry", ErrMalformed)
	}
	if k.IsExpired(now.Add(-MaxClockSkew)) {
		return fmt.Errorf("%w: tunnel key expired at %s", ErrExpired, k.ExpiryTime().Format(time.RFC3339))
	}

	return nil
}

func validateCandidates(u CandidateUpdate) error {
	const maxCandidates = 32

	if len(u.Added) > maxCandidates {
		return fmt.Errorf("%w: %d candidates, limit is %d", ErrTooLarge, len(u.Added), maxCandidates)
	}
	if len(u.Removed) > maxCandidates {
		return fmt.Errorf("%w: %d removals, limit is %d", ErrTooLarge, len(u.Removed), maxCandidates)
	}
	if len(u.Added) == 0 && len(u.Removed) == 0 && !u.Final {
		return fmt.Errorf("%w: candidate update carries nothing", ErrMalformed)
	}

	seen := make(map[string]bool, len(u.Added))
	for i, candidate := range u.Added {
		if candidate.ID == "" {
			return fmt.Errorf("%w: candidate %d has no id", ErrMalformed, i)
		}
		if seen[candidate.ID] {
			return fmt.Errorf("%w: candidate id %q repeats", ErrMalformed, candidate.ID)
		}
		seen[candidate.ID] = true

		if !candidate.Type.IsKnown() {
			return fmt.Errorf("%w: candidate type %q", ErrUnknownType, candidate.Type)
		}
		if candidate.Transport != "udp" {
			return fmt.Errorf("%w: candidate transport %q, only udp is defined", ErrUnknownType, candidate.Transport)
		}
		if !strings.Contains(candidate.Address, ":") {
			return fmt.Errorf("%w: candidate %q address must be host:port", ErrMalformed, candidate.ID)
		}
	}

	return nil
}

func validateClose(c SessionClose) error {
	switch c.Reason {
	case CloseNormal, CloseTimeout, ClosePolicy, CloseSuperseded, CloseError:
		return nil
	default:
		return fmt.Errorf("%w: close reason %q", ErrUnknownType, c.Reason)
	}
}

func validateError(e SessionError) error {
	switch e.Code {
	case ErrorUnsupportedVersion, ErrorUnauthorized, ErrorMalformed,
		ErrorExpired, ErrorReplay, ErrorUnsupportedCapability, ErrorInternal:
		return nil
	default:
		return fmt.Errorf("%w: error code %q", ErrUnknownType, e.Code)
	}
}

// DecodeEnvelope parses an envelope with strict limits.
//
// Unknown fields are rejected: a typo in a security-relevant key must fail
// loudly rather than leave the intended value at its default, and an attacker
// must not be able to smuggle data past the validator in a field we ignore.
func DecodeEnvelope(raw []byte) (Envelope, error) {
	if len(raw) > MaxEnvelopeSize {
		return Envelope{}, fmt.Errorf("%w: %d bytes, limit is %d", ErrTooLarge, len(raw), MaxEnvelopeSize)
	}
	if err := checkDepth(raw); err != nil {
		return Envelope{}, err
	}

	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()

	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	return envelope, nil
}

// DecodePayload parses a decrypted payload with the same strictness.
func DecodePayload(raw []byte) (Payload, error) {
	if len(raw) > MaxPayloadSize {
		return Payload{}, fmt.Errorf("%w: %d bytes, limit is %d", ErrTooLarge, len(raw), MaxPayloadSize)
	}
	if err := checkDepth(raw); err != nil {
		return Payload{}, err
	}

	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()

	var payload Payload
	if err := decoder.Decode(&payload); err != nil {
		return Payload{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	return payload, nil
}

// checkDepth rejects deeply nested JSON before the parser sees it.
//
// Go's decoder handles nesting without overflowing, but bounding it early keeps
// a pathological document from consuming time proportional to its nesting when
// everything about it is already going to be rejected.
func checkDepth(raw []byte) error {
	depth, max := 0, 0
	inString, escaped := false, false

	for _, b := range raw {
		switch {
		case escaped:
			escaped = false
		case b == '\\' && inString:
			escaped = true
		case b == '"':
			inString = !inString
		case inString:
			// Braces inside a string are data, not structure.
		case b == '{' || b == '[':
			depth++
			if depth > max {
				max = depth
			}
			if max > MaxJSONDepth {
				return fmt.Errorf("%w: nesting exceeds %d levels", ErrTooLarge, MaxJSONDepth)
			}
		case b == '}' || b == ']':
			depth--
		}
	}

	return nil
}

// abbreviate shortens a key for an error message. Errors reach logs, and a full
// key adds length without adding meaning.
func abbreviate(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8]
}
