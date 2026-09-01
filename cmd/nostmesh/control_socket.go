package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"
)

// controlSocketName is the socket the service listens on, inside the state
// directory so it follows the same ownership as everything else the node keeps.
const controlSocketName = "control.sock"

// controlSocketMode is the only acceptable permission set: the owner alone.
//
// The socket answers questions about who this node is connected to and why an
// attempt failed. That is not secret in the way a key is, but it describes the
// operator's peers, and a socket readable by every local user hands that to
// anything running on the box.
const controlSocketMode fs.FileMode = 0o600

// controlQuery is what a client asks for.
//
// There is one verb, and it reads. A socket that cannot change anything cannot
// be used to revoke a peer or tear down a tunnel, so a local user who reaches it
// gains information rather than control. Changing state goes through the
// configuration file and SIGHUP, which leaves a reviewable record.
type controlQuery struct {
	Query string `json:"query"`
}

// controlState is the service's answer.
type controlState struct {
	Node  string             `json:"node"`
	Peers []controlPeerState `json:"peers"`
}

// controlPeerState is what the service knows about one peer.
type controlPeerState struct {
	Peer     string `json:"peer"`
	Alias    string `json:"alias"`
	Phase    string `json:"phase"`
	Attempts int    `json:"attempts"`
	Since    string `json:"since,omitempty"`
	Reason   string `json:"reason,omitempty"`

	// HandshakeAge is how long ago the data plane last refreshed. It is the
	// quantity a held session is judged on, so an operator watching it grow can
	// see a teardown coming rather than learn about it afterwards.
	HandshakeAge string `json:"handshake_age,omitempty"`
}

// controlSocketPath returns where the socket lives for a state directory.
func controlSocketPath(stateDir string) string {
	return filepath.Join(stateDir, controlSocketName)
}

// listenControl opens the control socket.
//
// A socket left behind by a crashed service would make Listen fail, so a stale
// one is removed first — but only after confirming nothing is answering on it,
// since removing a live service's socket would silently orphan it.
func listenControl(path string) (net.Listener, error) {
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("another service is already listening on %s", path)
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("clearing stale socket: %w", err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("opening control socket: %w", err)
	}

	// Go creates the socket with the process umask applied, which may be wider
	// than intended. Narrow it, then confirm: refusing to serve is better than
	// serving on a socket anyone can read.
	if err := os.Chmod(path, controlSocketMode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restricting control socket: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("checking control socket: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		_ = listener.Close()
		return nil, fmt.Errorf("control socket has mode %04o, expected %04o", perm, controlSocketMode)
	}

	return listener, nil
}

// serveControl answers queries until the listener closes.
func serveControl(listener net.Listener, snapshot func() controlState) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go answerControl(conn, snapshot)
	}
}

// answerControl handles one connection: one request, one reply, close.
func answerControl(conn net.Conn, snapshot func() controlState) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil {
		return
	}

	var query controlQuery
	if err := json.NewDecoder(conn).Decode(&query); err != nil {
		return
	}
	if query.Query != "state" {
		// An unknown verb gets nothing rather than an error naming what is
		// supported: this socket has one job.
		return
	}

	_ = json.NewEncoder(conn).Encode(snapshot())
}

// queryControl asks a running service for its state.
func queryControl(path string) (controlState, error) {
	conn, err := net.DialTimeout("unix", path, controlTimeout)
	if err != nil {
		return controlState{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil {
		return controlState{}, err
	}

	if err := json.NewEncoder(conn).Encode(controlQuery{Query: "state"}); err != nil {
		return controlState{}, err
	}

	var state controlState
	if err := json.NewDecoder(conn).Decode(&state); err != nil {
		return controlState{}, err
	}
	return state, nil
}

// controlTimeout bounds a control exchange, which is local and should be
// instant.
const controlTimeout = 3 * time.Second
