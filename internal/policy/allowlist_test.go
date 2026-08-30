package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
)

func testPeer(seed byte) domain.NostrPublicKey {
	var key domain.NostrPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

// The property everything else rests on: an empty allowlist authorizes nobody.
// A policy engine that defaults to allow is a policy engine that fails open.
func TestEmptyAllowlistAuthorizesNobody(t *testing.T) {
	allowlist := NewAllowlist()

	for seed := range 10 {
		peer := testPeer(byte(seed * 20))
		for _, action := range []Action{ActionSession, ActionRoute, ActionTransit} {
			if err := allowlist.Check(peer, action); !errors.Is(err, ErrNotAuthorized) {
				t.Errorf("peer %d must be refused for %s, got: %v", seed, action, err)
			}
		}
	}
}

func TestGrantedPeerIsAuthorized(t *testing.T) {
	allowlist := NewAllowlist()
	peer := testPeer(1)

	if err := allowlist.Add(Grant{Peer: peer, Alias: "lab", Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}

	if err := allowlist.Check(peer, ActionSession); err != nil {
		t.Errorf("a granted peer must be authorized: %v", err)
	}
}

// Actions are separate because they carry different risk. A peer trusted to
// open a session is not thereby trusted to announce routes into this node.
func TestActionsAreNotInterchangeable(t *testing.T) {
	allowlist := NewAllowlist()
	peer := testPeer(1)

	if err := allowlist.Add(Grant{Peer: peer, Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}

	if err := allowlist.Check(peer, ActionSession); err != nil {
		t.Errorf("the granted action must be allowed: %v", err)
	}
	for _, denied := range []Action{ActionRoute, ActionTransit} {
		if err := allowlist.Check(peer, denied); !errors.Is(err, ErrNotAuthorized) {
			t.Errorf("%s must not be implied by a session grant, got: %v", denied, err)
		}
	}
}

// Revocation keeps the record, so an operator can tell a peer that was removed
// on purpose from one that was never added.
func TestRevocationIsDistinctFromAbsence(t *testing.T) {
	allowlist := NewAllowlist()
	known := testPeer(1)
	unknown := testPeer(100)

	if err := allowlist.Add(Grant{Peer: known, Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}
	if err := allowlist.Revoke(known); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	revokedErr := allowlist.Check(known, ActionSession)
	if !errors.Is(revokedErr, ErrRevoked) {
		t.Errorf("expected ErrRevoked, got: %v", revokedErr)
	}

	absentErr := allowlist.Check(unknown, ActionSession)
	if !errors.Is(absentErr, ErrNotAuthorized) {
		t.Errorf("expected ErrNotAuthorized, got: %v", absentErr)
	}

	if allowlist.Size() != 1 {
		t.Error("revocation must keep the record")
	}
}

func TestRevokingUnknownPeerFails(t *testing.T) {
	allowlist := NewAllowlist()

	if err := allowlist.Revoke(testPeer(1)); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("expected ErrNotAuthorized, got: %v", err)
	}
}

func TestRemoveDeletesTheRecord(t *testing.T) {
	allowlist := NewAllowlist()
	peer := testPeer(1)

	if err := allowlist.Add(Grant{Peer: peer, Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}
	allowlist.Remove(peer)

	if allowlist.Size() != 0 {
		t.Error("remove must delete the record")
	}
	if err := allowlist.Check(peer, ActionSession); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("expected ErrNotAuthorized, got: %v", err)
	}
}

// An alias is a label with no authority: two peers sharing one must not affect
// either's authorization.
func TestAliasCarriesNoAuthority(t *testing.T) {
	allowlist := NewAllowlist()

	granted := testPeer(1)
	impostor := testPeer(100)

	if err := allowlist.Add(Grant{Peer: granted, Alias: "trusted", Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}

	if err := allowlist.Check(impostor, ActionSession); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("an unlisted peer must be refused regardless of alias, got: %v", err)
	}
}

// Adding a grant for the same peer replaces it, so an operator narrowing
// permissions does not leave the old wider grant in place.
func TestAddReplacesExistingGrant(t *testing.T) {
	allowlist := NewAllowlist()
	peer := testPeer(1)

	if err := allowlist.Add(Grant{Peer: peer, Actions: []Action{ActionSession, ActionRoute}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}
	if err := allowlist.Add(Grant{Peer: peer, Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("replacing grant: %v", err)
	}

	if err := allowlist.Check(peer, ActionRoute); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("the narrowed grant must not retain the old action, got: %v", err)
	}
	if allowlist.Size() != 1 {
		t.Errorf("replacing must not add a record, size = %d", allowlist.Size())
	}
}

func TestAddRejectsIncompleteGrants(t *testing.T) {
	allowlist := NewAllowlist()

	t.Run("no peer", func(t *testing.T) {
		if err := allowlist.Add(Grant{Actions: []Action{ActionSession}}); err == nil {
			t.Error("a grant without a peer must be refused")
		}
	})

	t.Run("no actions", func(t *testing.T) {
		if err := allowlist.Add(Grant{Peer: testPeer(1)}); err == nil {
			t.Error("a grant without actions must be refused")
		}
	})
}

// A refusal reaches logs and sometimes the peer. It must not describe what
// would have worked.
func TestRefusalRevealsNothingUseful(t *testing.T) {
	allowlist := NewAllowlist()
	peer := testPeer(1)

	if err := allowlist.Add(Grant{Peer: peer, Alias: "secret-internal-name", Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}

	err := allowlist.Check(testPeer(200), ActionSession)
	if err == nil {
		t.Fatal("an unlisted peer must be refused")
	}

	message := err.Error()
	if strings.Contains(message, "secret-internal-name") {
		t.Errorf("the refusal leaks another peer's alias: %s", message)
	}
	if strings.Contains(message, testPeer(1).String()) {
		t.Errorf("the refusal leaks an authorized key: %s", message)
	}
}

// The allowlist is read on every inbound message and written by the operator,
// so it must be safe under concurrent access.
func TestAllowlistIsConcurrencySafe(t *testing.T) {
	allowlist := NewAllowlist()
	done := make(chan struct{})

	for worker := range 8 {
		go func(w int) {
			defer func() { done <- struct{}{} }()

			peer := testPeer(byte(w * 30))
			for range 50 {
				_ = allowlist.Add(Grant{Peer: peer, Actions: []Action{ActionSession}})
				_ = allowlist.Check(peer, ActionSession)
				_ = allowlist.Grants()
			}
		}(worker)
	}
	for range 8 {
		<-done
	}
}

// The Authorizer adapter must refuse exactly what Check refuses.
func TestAuthorizerMatchesCheck(t *testing.T) {
	allowlist := NewAllowlist()
	granted := testPeer(1)
	absent := testPeer(100)

	if err := allowlist.Add(Grant{Peer: granted, Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding grant: %v", err)
	}

	if err := allowlist.Authorize(granted); err != nil {
		t.Errorf("a granted peer must authorize: %v", err)
	}
	if err := allowlist.Authorize(absent); err == nil {
		t.Error("an unlisted peer must be refused")
	}
}
