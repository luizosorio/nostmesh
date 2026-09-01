package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The socket describes who this node connects to and why attempts fail. That is
// not secret the way a key is, but it is the operator's peer list, and a socket
// readable by every local user hands it to anything running on the box.
//
// Go applies the process umask when creating the socket, so a permissive umask
// would silently widen it. The service narrows it and then confirms.
func TestTheControlSocketIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, controlSocketName)

	// A umask that would otherwise leave the socket world-readable.
	previous := setUmask(0)
	defer setUmask(previous)

	listener, err := listenControl(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer func() { _ = listener.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("socket has mode %04o; anything running as another user can read the peer list", perm)
	}
}

// The socket answers the one question it exists for, and reports what the
// service knows rather than what the kernel does.
func TestTheControlSocketReportsState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, controlSocketName)

	listener, err := listenControl(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go serveControl(listener, func() controlState {
		return controlState{
			Node: "abcd1234",
			Peers: []controlPeerState{{
				Peer:     "beef0001",
				Alias:    "lab",
				Phase:    "retrying",
				Attempts: 3,
				Reason:   "no candidate path could be verified",
			}},
		}
	})

	state, err := queryControl(path)
	if err != nil {
		t.Fatalf("querying: %v", err)
	}

	if state.Node != "abcd1234" {
		t.Errorf("node is %q", state.Node)
	}
	if len(state.Peers) != 1 {
		t.Fatalf("%d peers, want 1", len(state.Peers))
	}
	if state.Peers[0].Attempts != 3 || state.Peers[0].Phase != "retrying" {
		t.Errorf("peer state is %+v", state.Peers[0])
	}
	if state.Peers[0].Reason == "" {
		t.Error("the reason an attempt failed is the point of asking, and it was dropped")
	}
}

// The socket is read-only, and that is its whole security argument: a local user
// who reaches it learns things but cannot revoke a peer or drop a tunnel.
//
// Anything other than the one read verb must produce nothing at all.
func TestTheControlSocketRefusesEverythingButReading(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, controlSocketName)

	listener, err := listenControl(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer func() { _ = listener.Close() }()

	var served bool
	go serveControl(listener, func() controlState {
		served = true
		return controlState{Node: "abcd1234"}
	})

	for _, verb := range []string{"revoke", "disconnect", "reload", "shutdown", ""} {
		conn, err := net.DialTimeout("unix", path, controlTimeout)
		if err != nil {
			t.Fatalf("dialling: %v", err)
		}

		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if err := json.NewEncoder(conn).Encode(controlQuery{Query: verb}); err != nil {
			_ = conn.Close()
			continue
		}

		var reply controlState
		err = json.NewDecoder(conn).Decode(&reply)
		_ = conn.Close()

		if err == nil {
			t.Errorf("the verb %q was answered; this socket must only read", verb)
		}
	}

	if served {
		t.Error("an unsupported verb reached the state snapshot")
	}
}

// A second service must not quietly take over the socket: the first would keep
// running while nothing could reach it.
func TestASecondServiceRefusesAnActiveSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, controlSocketName)

	first, err := listenControl(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer func() { _ = first.Close() }()

	go serveControl(first, func() controlState { return controlState{} })

	if _, err := listenControl(path); err == nil {
		t.Error("a second service took over a live socket; the first would be orphaned")
	}
}

// A socket left behind by a crashed service must not block a new one. The
// service is expected to recover on its own after a hard stop.
func TestAStaleSocketIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, controlSocketName)

	// A file where the socket was, with nothing listening: what a crash leaves.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seeding stale socket: %v", err)
	}

	listener, err := listenControl(path)
	if err != nil {
		t.Fatalf("a stale socket must not block a restart: %v", err)
	}
	_ = listener.Close()
}
