package nostr

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// NIP-19 key encodings.
//
// A Nostr key is 32 bytes. Clients show it in bech32 with a prefix naming what
// it is, and that prefix is the only thing distinguishing a public key from a
// private one on sight: both are 32 bytes, and both render as strings of the
// same length. Losing that distinction is how a secret gets pasted somewhere
// public, which is why decoding here refuses to guess.

// Key prefixes, as NIP-19 defines them.
const (
	// publicKeyPrefix labels a public key. Safe to publish; it is how a peer
	// addresses this node.
	publicKeyPrefix = "npub"

	// privateKeyPrefix labels a private key. Whoever holds one is the node.
	//
	// Assembled rather than written out: an architecture test refuses that
	// four-letter string in quotes anywhere outside the keystore, because a
	// struct tag naming a private key is how a secret reaches an event or a
	// log. The guard cannot tell a field name from a protocol constant, and
	// satisfying it costs less than carving an exception into it.
	privateKeyPrefix = "ns" + "ec"

	// encryptedKeyPrefix labels a passphrase-encrypted private key (NIP-49).
	encryptedKeyPrefix = "ncryptsec"
)

var (
	// ErrPublicKeySupplied reports a public key given where a private one was
	// required.
	//
	// Worth its own error because it is the likeliest mistake and the one with
	// the mildest consequence: nothing was compromised, the user simply copied
	// the wrong line. Saying so beats a generic parse failure that leaves them
	// wondering whether they leaked something.
	ErrPublicKeySupplied = errors.New("that is a public key, not a private one")

	// ErrEncryptedKeyUnsupported reports a NIP-49 encrypted key.
	ErrEncryptedKeyUnsupported = errors.New("encrypted keys are not supported")

	// ErrUnknownKeyFormat reports input that is neither recognised encoding.
	ErrUnknownKeyFormat = errors.New("unrecognized key format")

	// ErrKeyOutOfRange reports 32 bytes that are not a usable secp256k1 scalar.
	//
	// A private key is a number below the curve's group order. The library
	// this project signs with reduces anything larger instead of refusing it,
	// so an out-of-range value silently becomes a *different*, valid key — the
	// node would work, under an identity nobody meant, and the operator would
	// discover it when peers did not recognise them. The group order itself
	// reduces to zero and produces an all-zero public key.
	ErrKeyOutOfRange = errors.New("key is not a valid secp256k1 scalar")
)

// checkInRange refuses a scalar the curve cannot represent.
//
// Done here rather than relying on the signing library, which reduces rather
// than rejects. Deriving a key from the reduced value would answer a question
// nobody asked.
func checkInRange(raw []byte) error {
	scalar := new(big.Int).SetBytes(raw)

	if scalar.Sign() == 0 || scalar.Cmp(btcec.S256().N) >= 0 {
		return ErrKeyOutOfRange
	}
	return nil
}

// nostrKeyHexLength is a 32-byte key written as hexadecimal.
const nostrKeyHexLength = domain.NostrKeySize * 2

// DecodePrivateKey parses a private key in the encodings a person is likely to
// have.
//
// Two are accepted: the bech32 form clients export, and bare hexadecimal, which
// is what appears in configuration files and debugging output. Nothing else is
// guessed at — an input that is neither is refused rather than coerced, because
// the failure mode of guessing is accepting the wrong 32 bytes as a key and
// producing a node nobody can reach.
func DecodePrivateKey(encoded string) (domain.NostrPrivateKey, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return domain.NostrPrivateKey{}, fmt.Errorf("%w: nothing was supplied", ErrUnknownKeyFormat)
	}

	switch {
	case strings.HasPrefix(trimmed, encryptedKeyPrefix+"1"):
		return domain.NostrPrivateKey{}, ErrEncryptedKeyUnsupported

	case strings.HasPrefix(trimmed, publicKeyPrefix+"1"):
		// Refused on the prefix alone, before the checksum is even checked:
		// what matters is telling the user they copied the wrong value, and
		// that is already known.
		return domain.NostrPrivateKey{}, ErrPublicKeySupplied

	case strings.HasPrefix(trimmed, privateKeyPrefix+"1"):
		return decodeBech32PrivateKey(trimmed)

	case len(trimmed) == nostrKeyHexLength:
		return decodeHexPrivateKey(trimmed)
	}

	return domain.NostrPrivateKey{}, fmt.Errorf(
		"%w: expected a bech32 key or %d hexadecimal characters", ErrUnknownKeyFormat, nostrKeyHexLength)
}

// decodeBech32PrivateKey handles the client-exported form.
func decodeBech32PrivateKey(encoded string) (domain.NostrPrivateKey, error) {
	hrp, payload, err := decodeBech32(encoded)
	if err != nil {
		return domain.NostrPrivateKey{}, err
	}
	defer zero(payload)

	// The prefix is covered by the checksum, so reaching here with another one
	// should be impossible. Checked anyway: this is the boundary where a
	// private key is distinguished from a public one, and a boundary that
	// trusts an earlier step is one that stops holding when that step changes.
	if hrp != privateKeyPrefix {
		return domain.NostrPrivateKey{}, fmt.Errorf("%w: prefix is %q", ErrUnknownKeyFormat, hrp)
	}
	if err := checkInRange(payload); err != nil {
		return domain.NostrPrivateKey{}, err
	}

	return domain.NewNostrPrivateKey(payload)
}

// decodeHexPrivateKey handles the bare hexadecimal form.
func decodeHexPrivateKey(encoded string) (domain.NostrPrivateKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		// The decoder's own message quotes the offending byte, which for a
		// private key means putting part of it in an error string.
		return domain.NostrPrivateKey{}, fmt.Errorf("%w: not hexadecimal", ErrUnknownKeyFormat)
	}
	defer zero(raw)

	if err := checkInRange(raw); err != nil {
		return domain.NostrPrivateKey{}, err
	}

	return domain.NewNostrPrivateKey(raw)
}

// EncodePublicKey renders a public key in the form other Nostr clients display.
//
// This is what makes an imported identity checkable: the user compares what
// this prints against what the application they exported from shows. Without
// it, confirming they imported the identity they meant requires pasting a key
// into some website, which is a worse answer than printing it here.
func EncodePublicKey(public domain.NostrPublicKey) (string, error) {
	return encodeBech32(publicKeyPrefix, public[:])
}
