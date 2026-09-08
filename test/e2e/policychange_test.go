package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/policy"
)

// Policy changing while the mesh runs.
//
// M2.5 asks that access be denied when policy says so and that a partition not
// widen privileges. Both come down to one property: the decision that matters is
// the one in force when the effect happens, not the one that was in force when
// the peer was first authorized.

// Revoking a peer stops it connecting.
//
// The plainest form of the acceptance criterion "denied access does not get
// through". A revocation that only took effect after a restart would leave a
// peer connected for as long as the process lived.
func TestARevokedPeerCannotConnect(t *testing.T) {
	harness := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// It works first, so the refusal below is attributable to the revocation
	// rather than to anything else being wrong.
	if result := harness.Connect(ctx); result.Err != nil {
		t.Fatalf("the pair could not connect before revocation: %v", result.Err)
	}

	// Bob revokes Alice: the responder's policy is what decides.
	if err := harness.Bob.Allowlist.Revoke(harness.Alice.Public); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	result := harness.Connect(ctx)
	if result.Err == nil {
		t.Fatal("a revoked peer established a session")
	}
	if result.Established {
		t.Error("a revoked peer reached an established session")
	}
}

// Authorizing a peer lets it connect without a restart.
//
// The other direction, and the one an operator exercises most: adding a peer to
// the allowlist has to take effect on the next attempt. Requiring a restart
// would make every authorization an outage.
func TestANewlyAuthorizedPeerConnects(t *testing.T) {
	harness := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := harness.Bob.Allowlist.Revoke(harness.Alice.Public); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if result := harness.Connect(ctx); result.Err == nil {
		t.Fatal("the revocation did not take effect, so this proves nothing")
	}

	// Authorized again, with the same grant the harness gives every node.
	if err := harness.Bob.Allowlist.Add(policy.Grant{
		Peer:    harness.Alice.Public,
		Alias:   harness.Alice.Name,
		Actions: []policy.Action{policy.ActionSession},
	}); err != nil {
		t.Fatalf("authorizing: %v", err)
	}

	result := harness.Connect(ctx)
	if result.Err != nil {
		t.Fatalf("a newly authorized peer could not connect: %v", result.Err)
	}
}

// A partition does not widen what a peer may do.
//
// The acceptance criterion stated directly. A node that could not reach its
// relays might reasonably be more permissive — it cannot check anything — and
// that is exactly the reasoning this test exists to refute: policy is local, so
// losing the control plane changes nothing about what is allowed.
func TestAPartitionDoesNotWidenPrivileges(t *testing.T) {
	harness := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Revoked before the partition: the node knows it must refuse.
	if err := harness.Bob.Allowlist.Revoke(harness.Alice.Public); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	for i := range harness.Relays {
		harness.SetRelayDown(i, true)
	}
	if result := harness.Connect(ctx); result.Established {
		t.Fatal("a revoked peer established during a partition")
	}

	// And the refusal survives the partition lifting, which is where a node
	// that had quietly relaxed would give itself away.
	for i := range harness.Relays {
		harness.SetRelayDown(i, false)
	}

	result := harness.Connect(ctx)
	if result.Err == nil {
		t.Error("a revoked peer connected once the partition lifted")
	}
	if result.Established {
		t.Error("a revoked peer reached an established session after recovery")
	}
}

// Revoking one peer leaves the others connected.
//
// Isolation of policy, matching the isolation of failure the mesh already has.
// An operator removing one device must not find they have removed the mesh.
func TestRevokingOnePeerLeavesTheOthers(t *testing.T) {
	harness := meshHarness(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Two independent pairs, both working.
	if result := harness.ConnectPair(ctx, harness.Nodes[0], harness.Nodes[1]); result.Err != nil {
		t.Fatalf("the first pair could not connect: %v", result.Err)
	}
	if result := harness.ConnectPair(ctx, harness.Nodes[2], harness.Nodes[3]); result.Err != nil {
		t.Fatalf("the second pair could not connect: %v", result.Err)
	}

	// One side of the first pair revokes the other.
	if err := harness.Nodes[1].Allowlist.Revoke(harness.Nodes[0].Public); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	if result := harness.ConnectPair(ctx, harness.Nodes[0], harness.Nodes[1]); result.Err == nil {
		t.Error("the revoked pair still connects")
	}
	if result := harness.ConnectPair(ctx, harness.Nodes[2], harness.Nodes[3]); result.Err != nil {
		t.Errorf("revoking one peer disturbed an unrelated pair: %v", result.Err)
	}
}
