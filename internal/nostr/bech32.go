package nostr

import (
	"errors"
	"fmt"
	"strings"
)

// Bech32 encoding, as specified by BIP-173.
//
// This is the encoding Nostr clients use to render keys (NIP-19): the form a
// user sees when an application shows them their identity, and the form they
// paste when moving it somewhere else.
//
// It is implemented here rather than taken from a library because the obvious
// library — go-nostr's nip19 — imports the go-nostr root package, which NM-10
// forbids and an architecture test refuses: that package carries a WebSocket
// client, three JSON libraries and a URL parser, none of which this project
// needs, since the relay client is its own.
//
// Writing it is not the "never invent cryptography" rule being bent. Bech32 is
// a character encoding with a checksum: it makes a mistyped key detectable, and
// makes nothing secret. The security of a key does not depend on any property
// of this file. What it does depend on — that a corrupted key is rejected
// rather than silently accepted as a different key — is exactly what the
// checksum provides and what the tests here verify against the specification's
// own vectors.

// charset is the bech32 alphabet. It excludes "1", "b", "i" and "o" so that
// characters easily confused when read aloud or transcribed cannot both be
// valid.
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var (
	// ErrBech32Invalid reports a string that is not well-formed bech32.
	ErrBech32Invalid = errors.New("value is not valid bech32")

	// ErrBech32Checksum reports a checksum that does not match the data.
	//
	// Separate from ErrBech32Invalid because it means something specific and
	// actionable: the string has the right shape, so it was probably a key,
	// and a character was mistyped or the paste was cut short.
	ErrBech32Checksum = errors.New("checksum does not match")
)

// bech32MaxLength bounds what will be decoded.
//
// BIP-173 caps a bech32 string at 90 characters. NIP-19 raises that
// deliberately — "Bech32-formatted strings SHOULD be limited in size to 5000
// characters" — because the entities it defines carry relay hints and author
// keys alongside the identifier, and those do not fit in 90.
//
// The Nostr limit is the one that applies: this decodes keys as other Nostr
// clients write them. A bound still exists so a misdirected file is refused
// rather than buffered as though it were a key.
const bech32MaxLength = 5000

// decodeCharset maps a character to its 5-bit value, or -1.
var decodeCharset = buildDecodeCharset()

func buildDecodeCharset() [256]int8 {
	var table [256]int8
	for i := range table {
		table[i] = -1
	}
	for value, char := range charset {
		table[char] = int8(value) //nolint:gosec // charset indices are 0-31
	}
	return table
}

// polymod computes the BIP-173 checksum over a value sequence.
func polymod(values []byte) uint32 {
	generator := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i := range generator {
			if (top>>uint(i))&1 == 1 {
				checksum ^= generator[i]
			}
		}
	}
	return checksum
}

// expandHRP prepares the human-readable part for checksum computation, so that
// the prefix is covered: a public-key payload relabelled with the private-key
// prefix fails the checksum rather than decoding as a different kind of key.
func expandHRP(hrp string) []byte {
	expanded := make([]byte, 0, len(hrp)*2+1)
	for i := range len(hrp) {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := range len(hrp) {
		expanded = append(expanded, hrp[i]&31)
	}
	return expanded
}

// convertBits regroups a byte sequence between bit widths.
//
// Bech32 carries 5 bits per character while a key is 8-bit bytes, so encoding
// and decoding both have to regroup. Padding is added when growing to 5 and
// refused when shrinking to 8: leftover bits on the way in mean the input was
// not a whole number of bytes, which is a malformed key rather than a short one.
func convertBits(data []byte, from, to uint8, pad bool) ([]byte, error) {
	var accumulator uint32
	var bits uint8

	// The mask keeps every produced value inside `to` bits, and `to` is never
	// more than 8 here, so each fits a byte. Narrowing through the mask rather
	// than asserting it keeps that visible to a reader and to the compiler.
	maxValue := uint32(1)<<to - 1
	narrow := func(v uint32) byte { return byte(v & maxValue & 0xff) }
	converted := make([]byte, 0, len(data)*int(from)/int(to)+1)

	for _, value := range data {
		if value>>from != 0 {
			return nil, fmt.Errorf("%w: value %d exceeds %d bits", ErrBech32Invalid, value, from)
		}
		accumulator = accumulator<<from | uint32(value)
		bits += from

		for bits >= to {
			bits -= to
			converted = append(converted, narrow(accumulator>>bits))
		}
	}

	if pad {
		if bits > 0 {
			converted = append(converted, narrow(accumulator<<(to-bits)))
		}
		return converted, nil
	}

	// Not padding: whatever remains must be zero padding that the encoder
	// added, and there must be less than a full group of it. Anything else
	// means the payload does not decode to whole bytes.
	if bits >= from || accumulator<<(to-bits)&maxValue != 0 {
		return nil, fmt.Errorf("%w: %d bits left over", ErrBech32Invalid, bits)
	}
	return converted, nil
}

// encodeBech32 renders a payload under a human-readable prefix.
func encodeBech32(hrp string, payload []byte) (string, error) {
	if hrp == "" {
		return "", fmt.Errorf("%w: empty prefix", ErrBech32Invalid)
	}

	values, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}

	checksumInput := make([]byte, 0, len(hrp)*2+1+len(values)+6)
	checksumInput = append(checksumInput, expandHRP(hrp)...)
	checksumInput = append(checksumInput, values...)
	checksumInput = append(checksumInput, 0, 0, 0, 0, 0, 0)

	checksum := polymod(checksumInput) ^ 1

	var builder strings.Builder
	builder.WriteString(hrp)
	builder.WriteByte('1')
	for _, value := range values {
		builder.WriteByte(charset[value])
	}
	for i := range 6 {
		builder.WriteByte(charset[checksum>>uint(5*(5-i))&31])
	}
	return builder.String(), nil
}

// decodeBech32 parses a bech32 string into its prefix and payload.
func decodeBech32(encoded string) (hrp string, payload []byte, err error) {
	if len(encoded) > bech32MaxLength {
		return "", nil, fmt.Errorf("%w: %d characters", ErrBech32Invalid, len(encoded))
	}

	// Mixed case is refused rather than normalised. BIP-173 makes it invalid
	// because a checksum computed over one case does not cover the other, so
	// accepting it would mean accepting a string the specification says is
	// corrupt.
	lower, upper := strings.ToLower(encoded), strings.ToUpper(encoded)
	if encoded != lower && encoded != upper {
		return "", nil, fmt.Errorf("%w: mixed case", ErrBech32Invalid)
	}
	encoded = lower

	separator := strings.LastIndexByte(encoded, '1')
	if separator < 1 || separator+7 > len(encoded) {
		return "", nil, fmt.Errorf("%w: no separator and payload", ErrBech32Invalid)
	}

	hrp = encoded[:separator]
	for i := range len(hrp) {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, fmt.Errorf("%w: prefix has an unprintable character", ErrBech32Invalid)
		}
	}

	values := make([]byte, 0, len(encoded)-separator-1)
	for i := separator + 1; i < len(encoded); i++ {
		value := decodeCharset[encoded[i]]
		if value < 0 {
			return "", nil, fmt.Errorf("%w: %q is not in the alphabet", ErrBech32Invalid, encoded[i])
		}
		values = append(values, byte(value))
	}

	checksumInput := make([]byte, 0, len(hrp)*2+1+len(values))
	checksumInput = append(checksumInput, expandHRP(hrp)...)
	checksumInput = append(checksumInput, values...)
	if polymod(checksumInput) != 1 {
		return "", nil, ErrBech32Checksum
	}

	// The last six characters are the checksum, not payload.
	payload, err = convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}
