// Package policy decides what a peer may do.
//
// Every decision starts from deny. A valid signature proves who is asking; it
// grants nothing. This package is pure — it has no side effects and no
// dependency on transport or kernel — so a decision can be tested in isolation
// and audited by reading one file.
package policy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/luizosorio/nostmesh/internal/domain"
)

var (
	// ErrNotAuthorized reports a peer local policy does not allow.
	//
	// The message names the peer in abbreviated form and nothing else: a
	// detailed refusal tells an unauthorized party what would have worked.
	ErrNotAuthorized = errors.New("peer is not authorized")

	// ErrRevoked reports a peer that was authorized and no longer is.
	ErrRevoked = errors.New("peer authorization was revoked")
)

// Action is something a peer might be permitted to do.
//
// Separating actions matters because they carry different risk: opening a
// session is not the same as announcing a route, and a peer trusted for one is
// not automatically trusted for the other.
type Action string

const (
	// ActionSession is opening a tunnel session.
	ActionSession Action = "session"

	// ActionRoute is announcing a prefix. Reserved for MVP 2.
	ActionRoute Action = "route"

	// ActionTransit is offering or consuming transit. Reserved for MVP 4.
	ActionTransit Action = "transit"
)

// Grant is what a peer is permitted.
type Grant struct {
	// Peer is the authorized identity.
	Peer domain.NostrPublicKey

	// Alias is a local label. It carries no authority and never participates in
	// a decision — two peers may share an alias without consequence.
	Alias string

	// Actions lists what the peer may do. An action absent from this list is
	// refused, which is what makes the list an allowlist rather than a hint.
	Actions []Action

	// Revoked withdraws the grant while keeping the record, so an operator can
	// see that a peer was deliberately removed rather than never added.
	Revoked bool
}

// Allows reports whether the grant covers an action.
func (g Grant) Allows(action Action) bool {
	if g.Revoked {
		return false
	}
	for _, allowed := range g.Actions {
		if allowed == action {
			return true
		}
	}
	return false
}

// Allowlist is the set of peers local policy permits.
//
// It is the whole authorization surface for MVP 1: no roles, no inheritance, no
// wildcards. A richer policy engine arrives in MVP 2, and starting simple means
// the deny-by-default property is verifiable by inspection.
type Allowlist struct {
	mu     sync.RWMutex
	grants map[domain.NostrPublicKey]Grant
}

// NewAllowlist returns an empty allowlist, which authorizes nobody.
func NewAllowlist() *Allowlist {
	return &Allowlist{grants: make(map[domain.NostrPublicKey]Grant)}
}

// Add records a grant, replacing any existing one for the peer.
func (a *Allowlist) Add(grant Grant) error {
	if grant.Peer.IsZero() {
		return errors.New("a grant requires a peer identity")
	}
	if len(grant.Actions) == 0 {
		return errors.New("a grant requires at least one action")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.grants[grant.Peer] = grant
	return nil
}

// Revoke withdraws a peer's authorization, keeping the record.
func (a *Allowlist) Revoke(peer domain.NostrPublicKey) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	grant, known := a.grants[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrNotAuthorized, peer.Short())
	}

	grant.Revoked = true
	a.grants[peer] = grant
	return nil
}

// Remove deletes a peer's record entirely.
func (a *Allowlist) Remove(peer domain.NostrPublicKey) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.grants, peer)
}

// Check reports whether a peer may perform an action.
func (a *Allowlist) Check(peer domain.NostrPublicKey, action Action) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	grant, known := a.grants[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrNotAuthorized, peer.Short())
	}
	if grant.Revoked {
		return fmt.Errorf("%w: %s", ErrRevoked, peer.Short())
	}
	if !grant.Allows(action) {
		return fmt.Errorf("%w: %s may not %s", ErrNotAuthorized, peer.Short(), action)
	}
	return nil
}

// Authorize satisfies the session package's Authorizer for tunnel sessions.
func (a *Allowlist) Authorize(peer domain.NostrPublicKey) error {
	return a.Check(peer, ActionSession)
}

// Grants returns every recorded grant, for display.
func (a *Allowlist) Grants() []Grant {
	a.mu.RLock()
	defer a.mu.RUnlock()

	grants := make([]Grant, 0, len(a.grants))
	for _, grant := range a.grants {
		grants = append(grants, grant)
	}
	return grants
}

// Size returns how many peers are recorded.
func (a *Allowlist) Size() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return len(a.grants)
}
