package netconfig

import (
	"encoding/hex"
	"fmt"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// The manifest's file format.
//
// The domain types hold keys as byte arrays, which JSON renders as lists of
// thirty-two numbers — unreadable in a file an operator inspects, and fragile
// against a reordering nobody would notice. So the document is its own shape,
// with everything hex-encoded, and converting between the two is explicit.
//
// Keeping the wire format separate from the domain type is also what stops a
// change to one silently changing the other: the manifest's digest covers the
// domain values, and a document that decoded differently would verify against a
// signature over something else.

// document is a signed manifest as it appears on disk.
type document struct {
	Manifest  manifestDocument `json:"manifest"`
	Issuer    string           `json:"issuer"`
	Signature string           `json:"signature"`
}

// manifestDocument is the manifest's own file shape.
type manifestDocument struct {
	NetworkID string           `json:"network_id"`
	Name      string           `json:"name,omitempty"`
	Version   uint64           `json:"version"`
	Subnets   []uint16         `json:"subnets,omitempty"`
	Members   []memberDocument `json:"members"`
}

// memberDocument is one member's file shape.
type memberDocument struct {
	PublicKey string `json:"public_key"`
	Alias     string `json:"alias,omitempty"`
	IPv4      string `json:"ipv4,omitempty"`
}

// decode converts a document into the domain type.
//
// Every field is checked rather than coerced: this is the boundary where a file
// somebody could have written by hand becomes something the rest of the code
// treats as structured, and a malformed value accepted here reappears as a
// confusing failure much later.
func (d document) decode() (domain.SignedManifest, error) {
	networkID, err := decodeNetworkID(d.Manifest.NetworkID)
	if err != nil {
		return domain.SignedManifest{}, err
	}

	issuer, err := domain.ParseNostrPublicKey(d.Issuer)
	if err != nil {
		return domain.SignedManifest{}, fmt.Errorf("%w: issuer: %w", domain.ErrManifestMalformed, err)
	}

	signature, err := hex.DecodeString(d.Signature)
	if err != nil {
		return domain.SignedManifest{}, fmt.Errorf("%w: signature is not hex", domain.ErrManifestMalformed)
	}

	members := make([]domain.Member, 0, len(d.Manifest.Members))
	for i, member := range d.Manifest.Members {
		key, err := domain.ParseNostrPublicKey(member.PublicKey)
		if err != nil {
			return domain.SignedManifest{}, fmt.Errorf("%w: member %d: %w",
				domain.ErrManifestMalformed, i, err)
		}
		members = append(members, domain.Member{
			PublicKey: key,
			Alias:     member.Alias,
			IPv4:      member.IPv4,
		})
	}

	return domain.SignedManifest{
		Manifest: domain.Manifest{
			NetworkID: networkID,
			Name:      d.Manifest.Name,
			Version:   d.Manifest.Version,
			Subnets:   d.Manifest.Subnets,
			Members:   members,
		},
		Issuer:    issuer,
		Signature: signature,
	}, nil
}

// encodeDocument converts a signed manifest into its file shape.
//
// Exported behaviour rather than a test helper: whatever writes a manifest has
// to produce exactly what decode expects, and having one function for it is what
// keeps the two from drifting.
func encodeDocument(signed domain.SignedManifest) document {
	members := make([]memberDocument, 0, len(signed.Manifest.Members))
	for _, member := range signed.Manifest.Members {
		members = append(members, memberDocument{
			PublicKey: member.PublicKey.String(),
			Alias:     member.Alias,
			IPv4:      member.IPv4,
		})
	}

	return document{
		Manifest: manifestDocument{
			NetworkID: hex.EncodeToString(signed.Manifest.NetworkID[:]),
			Name:      signed.Manifest.Name,
			Version:   signed.Manifest.Version,
			Subnets:   signed.Manifest.Subnets,
			Members:   members,
		},
		Issuer:    signed.Issuer.String(),
		Signature: hex.EncodeToString(signed.Signature),
	}
}

// decodeNetworkID parses a hex-encoded network identifier.
func decodeNetworkID(encoded string) (domain.NetworkID, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return domain.NetworkID{}, fmt.Errorf("%w: network id is not hex", domain.ErrManifestMalformed)
	}

	id, err := domain.NewNetworkID(raw)
	if err != nil {
		return domain.NetworkID{}, fmt.Errorf("%w: network id: %w", domain.ErrManifestMalformed, err)
	}
	return id, nil
}
