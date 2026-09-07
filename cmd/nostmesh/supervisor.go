package main

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// supervisor owns what every session shares.
//
// Before this, each connection attempt built its own netlink controller and its
// own SessionManager. That made two things impossible: `max_sessions` never
// fired, because a manager holding one session never reached a limit counted
// across all of them; and no single place knew a peer's history, so the worker
// kept a parallel copy of it for `nostmesh state` to read.
//
// What is shared is deliberately narrow — the kernel handle and the session
// table. Everything a session can lose on its own, it still owns on its own: its
// transport, its relay connections, its interface. That is what keeps one peer
// failing from being every peer failing.
type supervisor struct {
	log *slog.Logger

	// controller is the netlink handle, opened once.
	//
	// A handle per attempt meant opening and closing a socket on every retry,
	// and it is what forced the session table to be per-attempt with it. Shared
	// here it must outlive every session: closing it while one is up would take
	// the data plane away from all of them at once, which is the failure this
	// type has to be careful about rather than the one it introduces — the
	// alternative was a table that could not count.
	controller wireguard.Controller

	// closeController releases the handle at shutdown, and only then.
	closeController func() error

	// manager is the one session table. Every phase transition, roam and
	// teardown goes through it, so `max_sessions` counts what it says it counts.
	manager *orchestrator.SessionManager

	// netstate applies changes transactionally, sharing the journal directory.
	netstate *netstate.Manager

	// answered records sessions already responded to, so a replayed request is
	// not answered twice.
	answered *orchestrator.AnsweredSessions

	// mu guards the slot table below.
	mu sync.Mutex

	// slots records which interface and port each peer holds, so two peers
	// cannot be handed the same pair.
	slots map[domain.NostrPublicKey]peerSlot
}

// newSupervisor opens what the sessions share.
//
// The caller closes it. Failing partway releases what was already opened rather
// than leaking a netlink socket for the life of the process.
func newSupervisor(cfg config.Config, log *slog.Logger) (*supervisor, error) {
	controller, closeController, err := wireguard.NewController()
	if err != nil {
		return nil, err
	}

	clock := domain.SystemClock{}
	journal := netstate.NewJournalStore(journalDir(cfg.Node.StateDir))
	netManager := netstate.NewManager(controller, journal, clock).WithLogger(log)

	manager, err := orchestrator.NewSessionManager(orchestrator.SessionManagerOptions{
		Controller:  controller,
		NetState:    netManager,
		Clock:       clock,
		MaxSessions: cfg.Policy.MaxSessions,
	})
	if err != nil {
		_ = closeController()
		return nil, err
	}

	return &supervisor{
		log:             log,
		controller:      controller,
		closeController: closeController,
		manager:         manager,
		netstate:        netManager,
		answered:        orchestrator.NewAnsweredSessions(clock.Now),
		slots:           make(map[domain.NostrPublicKey]peerSlot),
	}, nil
}

// Close releases the shared handle.
//
// Only at shutdown. Every session is gone by then, since the workers are stopped
// before this runs — calling it earlier would take the data plane from sessions
// that are still up.
func (s *supervisor) Close() error {
	if s.closeController == nil {
		return nil
	}
	return s.closeController()
}

// Claim reserves a peer's interface and port.
//
// Reserved rather than merely derived, so that two peers deriving the same pair
// are refused here — with both named, while the reason is still visible — rather
// than at a bind failure or, worse, by one silently rewriting the other's kernel
// state.
func (s *supervisor) Claim(peer domain.NostrPublicKey, basePort int) (peerSlot, error) {
	slot, err := slotFor(peer, basePort)
	if err != nil {
		return peerSlot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-claiming is the ordinary case: a worker retries and asks again for the
	// slot it already holds. The peer must get the same one, or the mapping its
	// peer verified would be abandoned on every retry.
	if held, exists := s.slots[peer]; exists {
		return held, nil
	}

	for other, held := range s.slots {
		if held.Interface == slot.Interface {
			return peerSlot{}, fmt.Errorf("%s and %s both derive interface %s",
				other.Short(), peer.Short(), slot.Interface)
		}
		if held.Port == slot.Port && slot.Port != 0 {
			return peerSlot{}, fmt.Errorf("%s and %s both derive port %d",
				other.Short(), peer.Short(), slot.Port)
		}
	}

	s.slots[peer] = slot
	return slot, nil
}

// Release gives up a peer's slot.
//
// Called when a worker stops for good, not between attempts: a slot released on
// every retry would be free for another peer to take, and the returning worker
// would come back on a different port than the one its peer verified.
func (s *supervisor) Release(peer domain.NostrPublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.slots, peer)
}

// Sessions reports what the shared table currently holds.
//
// One source rather than each worker's copy. A worker's view was only ever
// necessary because no manager outlived an attempt.
func (s *supervisor) Sessions() []orchestrator.SessionState {
	return s.manager.List()
}

// CloseSession removes a peer's session from the shared table.
//
// A worker ending an attempt leaves the table holding a session that no longer
// exists, and the next Begin for that peer would be refused as a duplicate. The
// error is deliberately dropped: a session already absent is the state wanted.
func (s *supervisor) CloseSession(peer domain.NostrPublicKey) {
	if err := s.manager.Close(peer); err != nil {
		s.log.Debug("session was already closed",
			observability.Event("session.close.skipped"),
			observability.Peer(peer))
	}
}
