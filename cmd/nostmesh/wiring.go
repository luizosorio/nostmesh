package main

import (
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/nostr"
)

// init wires the cryptographic backend into the identity package.
//
// internal/identity must not import internal/nostr: the keystore is domain
// logic and stays testable without cryptography, and the architecture test
// enforces that boundary. The composition happens here instead, in the one
// place that legitimately knows about both.
func init() {
	identity.DeriveNostrPublicKey = nostr.DerivePublicKey
}
