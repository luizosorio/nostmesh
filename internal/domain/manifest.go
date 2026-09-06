package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The network manifest, per NM-21.
//
// A manifest says what a network is: who its members are, which prefixes it
// occupies, and which version of that statement this is. It is signed by an
// issuer the operator pins locally, which is what keeps it local intent obtained
// remotely rather than remote authority — a manifest signed by anyone else is
// discarded without being read.
//
// Nothing here configures anything. The manifest supplies a prefix and a member
// list; what a node installs is derived from that by local policy.

// Manifest limits, checked before anything expensive happens.
const (
	// MaxManifestMembers bounds a network's size.
	//
	// Generous for MVP 2, which targets tens of peers, and bounded so that a
	// manifest cannot be used to make a node allocate without limit.
	MaxManifestMembers = 4096

	// MaxManifestSubnets bounds how many subnets a network may carve.
	MaxManifestSubnets = 256

	// MaxNetworkNameLength bounds the human-readable label.
	MaxNetworkNameLength = 64
)

var (
	// ErrManifestMalformed reports a manifest that does not parse or fails a
	// structural check.
	ErrManifestMalformed = errors.New("manifest is malformed")

	// ErrManifestUnsigned reports a manifest with no signature.
	ErrManifestUnsigned = errors.New("manifest is not signed")

	// ErrManifestWrongIssuer reports a manifest signed by somebody other than
	// the issuer this node pinned.
	//
	// This is the check that makes a manifest local intent: the operator names
	// the key, and anything else is not this network's manifest whatever it
	// claims inside.
	ErrManifestWrongIssuer = errors.New("manifest is not from the pinned issuer")

	// ErrManifestRollback reports a manifest older than the one already held.
	//
	// A relay keeps events and replays them. Without this, an old manifest
	// replayed from storage would renumber a working network backwards.
	ErrManifestRollback = errors.New("manifest version is older than the one held")

	// ErrMemberNotFound reports an identity absent from the manifest.
	ErrMemberNotFound = errors.New("identity is not a member of this network")
)

// Member is one participant in a network.
type Member struct {
	// PublicKey is the member's durable Nostr identity. It is what the address
	// is derived from, and what a signature authenticates.
	PublicKey NostrPublicKey `json:"public_key"`

	// Alias is a human-readable label with no authority. Two members may share
	// one; nothing is decided by it.
	Alias string `json:"alias,omitempty"`

	// IPv4 is an explicitly assigned address, in CIDR notation.
	//
	// Assigned rather than derived, and empty for most members. NM-21 measured
	// why: twenty nodes in a /24 collide more often than not, so IPv4 is a
	// compatibility affordance an operator allocates by hand, not something a
	// hash can be trusted to produce.
	IPv4 string `json:"ipv4,omitempty"`
}

// Manifest describes a network.
//
// The salt is deliberately absent. It is shared out of band between members and
// never published, which is what stops a relay operator holding every event from
// deriving a single address.
type Manifest struct {
	// NetworkID names the network and determines its prefix.
	NetworkID NetworkID `json:"network_id"`

	// Name is a human-readable label, with no authority.
	Name string `json:"name,omitempty"`

	// Version is monotonic. A manifest carrying a version at or below the one
	// already held is refused rather than applied.
	Version uint64 `json:"version"`

	// Subnets are the subnet ids this network uses. Empty means subnet zero
	// alone, which is what a network that never carves one wants.
	Subnets []uint16 `json:"subnets,omitempty"`

	// Members are the identities that belong to the network.
	Members []Member `json:"members"`
}

// Validate checks a manifest's structure.
//
// Structural only: it says nothing about whether the manifest is authentic,
// which is the signature's job, or whether it may replace what is held, which is
// the version's. Keeping the three apart means a caller cannot accidentally
// satisfy one by passing another.
func (m Manifest) Validate() error {
	if m.Version == 0 {
		// Zero is reserved for "no manifest held", so a real one starts at one.
		// Without this a first manifest could never be distinguished from none.
		return fmt.Errorf("%w: version must be at least 1", ErrManifestMalformed)
	}
	if len(m.Name) > MaxNetworkNameLength {
		return fmt.Errorf("%w: name is %d characters, limit is %d",
			ErrManifestMalformed, len(m.Name), MaxNetworkNameLength)
	}
	if len(m.Members) == 0 {
		return fmt.Errorf("%w: a network with no members addresses nobody", ErrManifestMalformed)
	}
	if len(m.Members) > MaxManifestMembers {
		return fmt.Errorf("%w: %d members, limit is %d",
			ErrManifestMalformed, len(m.Members), MaxManifestMembers)
	}
	if len(m.Subnets) > MaxManifestSubnets {
		return fmt.Errorf("%w: %d subnets, limit is %d",
			ErrManifestMalformed, len(m.Subnets), MaxManifestSubnets)
	}

	seen := make(map[NostrPublicKey]struct{}, len(m.Members))
	for i, member := range m.Members {
		if member.PublicKey.IsZero() {
			return fmt.Errorf("%w: member %d has no public key", ErrManifestMalformed, i)
		}
		if _, duplicate := seen[member.PublicKey]; duplicate {
			// Two entries for one identity would make membership ambiguous, and
			// a later one could silently override an earlier IPv4 assignment.
			return fmt.Errorf("%w: %s appears twice", ErrManifestMalformed, member.PublicKey.Short())
		}
		seen[member.PublicKey] = struct{}{}
	}

	return nil
}

// Subnet returns the subnet a network uses, given its index.
//
// A manifest with no subnets listed uses subnet zero, so a network that never
// needed to carve one does not have to say so.
func (m Manifest) Subnet(index int) uint16 {
	if len(m.Subnets) == 0 {
		return 0
	}
	if index < 0 || index >= len(m.Subnets) {
		return m.Subnets[0]
	}
	return m.Subnets[index]
}

// Member returns one member by identity.
func (m Manifest) Member(key NostrPublicKey) (Member, error) {
	for _, member := range m.Members {
		if member.PublicKey == key {
			return member, nil
		}
	}
	return Member{}, fmt.Errorf("%w: %s", ErrMemberNotFound, key.Short())
}

// Digest returns what a signature over this manifest covers.
//
// Canonical by construction rather than by serializing a struct: field order,
// omitted empties and map iteration all make an encoder's output depend on
// things that are not the content. Two nodes computing different digests for the
// same manifest would each conclude the other's signature was forged.
//
// Every field is length-prefixed, so no two different manifests can produce the
// same byte string by rearranging where one field ends and the next begins.
func (m Manifest) Digest() [32]byte {
	hash := sha256.New()

	// Lengths are written as 64 bits rather than 32. A length that overflowed
	// its prefix would let two different manifests hash alike, which is the one
	// thing this construction exists to prevent — and a bound checked elsewhere
	// is not something a digest should rely on.
	writeField := func(label string, value []byte) {
		hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(label))))
		hash.Write([]byte(label))
		hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(value))))
		hash.Write(value)
	}

	writeField("domain", []byte("nostmesh/manifest/v1"))
	writeField("network_id", m.NetworkID[:])
	writeField("name", []byte(m.Name))
	writeField("version", binary.BigEndian.AppendUint64(nil, m.Version))

	subnets := make([]byte, 0, len(m.Subnets)*2)
	for _, subnet := range slices.Sorted(slices.Values(m.Subnets)) {
		subnets = binary.BigEndian.AppendUint16(subnets, subnet)
	}
	writeField("subnets", subnets)

	// Members are sorted so that two nodes listing them differently still agree.
	// The order a manifest was written in is not part of what it says.
	members := slices.Clone(m.Members)
	slices.SortFunc(members, func(a, b Member) int {
		return strings.Compare(a.PublicKey.String(), b.PublicKey.String())
	})

	writeField("member_count", binary.BigEndian.AppendUint64(nil, uint64(len(members))))
	for _, member := range members {
		writeField("member_key", member.PublicKey[:])
		writeField("member_alias", []byte(member.Alias))
		writeField("member_ipv4", []byte(member.IPv4))
	}

	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// SignedManifest is a manifest with its issuer and signature.
type SignedManifest struct {
	Manifest Manifest `json:"manifest"`

	// Issuer is the identity that signed it.
	Issuer NostrPublicKey `json:"issuer"`

	// Signature covers Manifest.Digest().
	Signature []byte `json:"signature"`
}

// ManifestVerifier checks a signature.
//
// A port rather than an import: the core cannot reach the cryptography, so the
// implementation is wired in at the composition point the way identity.Signer
// already is. Keeping it an interface is also what lets the manifest logic be
// tested without a curve.
type ManifestVerifier interface {
	Verify(key NostrPublicKey, digest, signature []byte) error
}

// Accept checks a manifest and decides whether it may replace what is held.
//
// The order is deliberate and cheapest-first: structure, then issuer, then
// signature, then version. A malformed manifest costs no cryptography, and one
// from a stranger is refused before this node spends anything verifying it.
//
// Passing zero for heldVersion means nothing is held yet.
func Accept(signed SignedManifest, pinnedIssuer NostrPublicKey, heldVersion uint64, verifier ManifestVerifier) error {
	if err := signed.Manifest.Validate(); err != nil {
		return err
	}
	if len(signed.Signature) == 0 {
		return ErrManifestUnsigned
	}

	// Checked before the signature, and against the key the operator pinned
	// rather than the one the document names: a manifest that signs itself with
	// its own claimed issuer would otherwise verify perfectly.
	if pinnedIssuer.IsZero() {
		return fmt.Errorf("%w: no issuer is pinned, so nothing can be trusted", ErrManifestWrongIssuer)
	}
	if signed.Issuer != pinnedIssuer {
		return fmt.Errorf("%w: signed by %s, expected %s",
			ErrManifestWrongIssuer, signed.Issuer.Short(), pinnedIssuer.Short())
	}

	if verifier == nil {
		// Refused rather than skipped. A nil verifier means nothing checked the
		// signature, and treating that as success is how an unauthenticated
		// manifest gets applied.
		return fmt.Errorf("%w: no verifier was supplied", ErrManifestUnsigned)
	}

	digest := signed.Manifest.Digest()
	if err := verifier.Verify(pinnedIssuer, digest[:], signed.Signature); err != nil {
		return fmt.Errorf("%w: %w", ErrManifestMalformed, err)
	}

	// Last, because a rollback is a valid document this node simply already has
	// something newer than. Reporting it before the signature would tell a
	// stranger which versions this node holds.
	if signed.Manifest.Version <= heldVersion {
		return fmt.Errorf("%w: offered %d, holding %d",
			ErrManifestRollback, signed.Manifest.Version, heldVersion)
	}

	return nil
}
