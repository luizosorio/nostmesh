// Package netconfig turns a node's configuration into its overlay address.
//
// It sits outside the core because it reads files, and outside cmd/ because the
// decision it makes — derived address or manually configured one — is worth
// testing on its own rather than through a command.
package netconfig

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
)

// ErrNotConfigured reports a node with neither a network nor a manual address.
//
// Distinct from a failure, because it is what a node that never wanted an
// overlay address looks like — the caller decides whether that is a problem.
var ErrNotConfigured = errors.New("no overlay address is configured")

// Resolution is what a node concluded about its own address.
type Resolution struct {
	// Address is what the node installs on its interface.
	Address netip.Prefix

	// Derived says where the address came from. False means it was written in
	// the configuration file by hand, which is the MVP 1 behaviour.
	Derived bool

	// Allocation is the whole network's table, present only when derived. It is
	// what lets a node compute a peer's address rather than be told it.
	Allocation domain.Allocation

	// Manifest is the manifest the allocation came from, present only when
	// derived.
	Manifest domain.Manifest
}

// Resolve decides a node's overlay address.
//
// A configured network wins; a node without one falls back to the manually
// chosen address, which is what every deployment before NM-21 used and must keep
// using. Nothing here is best-effort: a network that is configured but cannot be
// loaded is an error rather than a quiet fall back to manual, because an operator
// who configured one and silently got the other has a node that is not on the
// network they think it is.
func Resolve(cfg config.Config, self domain.NostrPublicKey, verifier domain.ManifestVerifier) (Resolution, error) {
	if cfg.Network.Enabled() {
		return resolveFromNetwork(cfg, self, verifier)
	}

	if cfg.Node.OverlayAddress == "" {
		return Resolution{}, ErrNotConfigured
	}

	address, err := netip.ParsePrefix(cfg.Node.OverlayAddress)
	if err != nil {
		return Resolution{}, fmt.Errorf("node overlay address: %w", err)
	}
	return Resolution{Address: address}, nil
}

// resolveFromNetwork derives an address from the configured manifest.
func resolveFromNetwork(cfg config.Config, self domain.NostrPublicKey, verifier domain.ManifestVerifier) (Resolution, error) {
	issuer, err := domain.ParseNostrPublicKey(cfg.Network.Issuer)
	if err != nil {
		return Resolution{}, fmt.Errorf("network issuer: %w", err)
	}

	rawSalt, err := hex.DecodeString(cfg.Network.Salt)
	if err != nil {
		return Resolution{}, errors.New("network salt is not hex")
	}
	salt, err := domain.NewNetworkSalt(rawSalt)
	if err != nil {
		return Resolution{}, fmt.Errorf("network salt: %w", err)
	}

	signed, err := LoadManifest(cfg.Network.Manifest)
	if err != nil {
		return Resolution{}, err
	}

	// Held version zero: the manifest on disk is the only one this node has, so
	// there is nothing yet to roll back from. Rollback protection belongs where
	// a manifest is replaced, which is the transport's delivery rather than
	// this one.
	if err := domain.Accept(signed, issuer, 0, verifier); err != nil {
		return Resolution{}, fmt.Errorf("network manifest: %w", err)
	}

	// Checked before allocating, because two members handed the same address by
	// hand is an operator's mistake that the derivation cannot resolve.
	if err := domain.CheckIPv4Conflicts(signed.Manifest); err != nil {
		return Resolution{}, fmt.Errorf("network manifest: %w", err)
	}

	allocation, err := domain.Allocate(signed.Manifest, salt, cfg.Network.Subnet)
	if err != nil {
		return Resolution{}, fmt.Errorf("allocating addresses: %w", err)
	}

	assignment, err := allocation.For(self)
	if err != nil {
		// A node not in its own network's manifest would derive nothing. Saying
		// so plainly beats installing no address and failing later at a layer
		// that cannot explain why.
		return Resolution{}, fmt.Errorf("this node is not a member of the configured network: %w", err)
	}

	return Resolution{
		Address:    netip.PrefixFrom(assignment.Address, 128),
		Derived:    true,
		Allocation: allocation,
		Manifest:   signed.Manifest,
	}, nil
}

// LoadManifest reads a signed manifest from disk.
//
// It parses and nothing more: whether the manifest may be believed is decided by
// domain.Accept, and keeping the two apart means a caller cannot act on a
// manifest it merely managed to read.
func LoadManifest(path string) (domain.SignedManifest, error) {
	// The path is operator-supplied configuration, and validation has already
	// refused a relative one.
	content, err := os.ReadFile(path) //nolint:gosec // operator-supplied path by design
	if err != nil {
		return domain.SignedManifest{}, fmt.Errorf("reading network manifest: %w", err)
	}

	var doc document
	if err := json.Unmarshal(content, &doc); err != nil {
		return domain.SignedManifest{}, fmt.Errorf("%w: %s does not parse",
			domain.ErrManifestMalformed, path)
	}
	return doc.decode()
}
