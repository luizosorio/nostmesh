package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/policy"
	"github.com/luizosorio/nostmesh/internal/protocol"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// service runs sessions with every authorized peer for as long as it is up.
//
// Two nodes connect only if one is listening when the other publishes. A
// process that runs for the length of one attempt cannot promise that: it
// arrives after requests were published and answers whichever the relay kept,
// while its peer has moved on. Measured between two real hosts, that produced a
// pair permanently answering each other's abandoned sessions.
//
// Running continuously removes the race rather than arbitrating it. Every peer
// gets a worker that is always willing to answer and always willing to open,
// and which of the two happens is settled by the pair, not by a command name.
type service struct {
	cfg    config.Config
	log    *slog.Logger
	self   domain.NostrPublicKey
	config string

	mu      sync.Mutex
	workers map[domain.NostrPublicKey]*peerWorker

	// answered is shared by every worker and outlives their attempts, so a
	// session answered once is not answered again on the next poll.
	answered *orchestrator.AnsweredSessions

	// noticesSent counts revocation notices attempted. A test asserting the
	// boundary needs to see the decision, not guess at it from how long a
	// teardown took.
	noticesSent int
}

// peerWorker keeps trying to hold a session with one peer.
type peerWorker struct {
	peer  domain.NostrPublicKey
	alias string
	log   *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}

	// state is what `nostmesh state` reports. It is kept here rather than read
	// from a SessionManager because each attempt builds its own, so no single
	// manager sees the peer's history.
	stateMu  sync.Mutex
	phase    string
	attempts int
	since    time.Time
	reason   string

	// established records that a session with this peer once worked, which
	// decides whether revoking it is announced. See notifyRevoked.
	established bool

	// session is the conversation to name in a close, kept from the last
	// established session.
	session string

	// lastHandshake is when the data plane last refreshed, for the control
	// socket. It is the quantity the hold acts on, so an operator watching it
	// approach the limit can see a teardown coming.
	lastHandshake time.Time
}

// established reports whether this worker ever held a session.
func (w *peerWorker) hadSession() (string, bool) {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	return w.session, w.established
}

// recordSession keeps the conversation id a close would have to name.
//
// Without it a revocation notice has no session to reference and is silently
// dropped, so the peer is never told its authorization ended.
func (w *peerWorker) recordSession(id string) {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	if id != "" {
		w.session = id
	}
}

// observeHold notes that the session is still carrying.
func (w *peerWorker) observeHold(state wireguard.PeerState) {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	w.phase = "established"
	w.reason = ""
	w.lastHandshake = state.LastHandshake
}

// observe records where this worker stands.
func (w *peerWorker) observe(phase, reason string, attempts int) {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	if w.phase != phase {
		w.since = time.Now()
	}
	w.phase = phase
	w.reason = reason
	w.attempts = attempts
}

// recordEstablished notes that a session with this peer worked.
func (w *peerWorker) recordEstablished() {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	w.established = true
}

// snapshot reports this worker's state.
func (w *peerWorker) snapshot() controlPeerState {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	state := controlPeerState{
		Peer:     w.peer.Short(),
		Alias:    w.alias,
		Phase:    w.phase,
		Attempts: w.attempts,
		Reason:   w.reason,
	}
	if !w.since.IsZero() {
		state.Since = w.since.UTC().Format(time.RFC3339)
	}
	if !w.lastHandshake.IsZero() {
		state.HandshakeAge = time.Since(w.lastHandshake).Truncate(time.Second).String()
	}
	return state
}

// recoverHostState removes what an earlier run left behind.
//
// Failing here is reported and not fatal: the peer workers surface the same
// problem as a bind failure with a clearer message, and refusing to start would
// turn recoverable residue into an outage.
func (s *service) recoverHostState(ctx context.Context) {
	instance, cleanup, err := buildOrchestrator(s.cfg)
	if err != nil {
		s.log.Warn("could not check for leftover state",
			slog.String("event", "service.recovery.skipped"),
			slog.String("error", err.Error()))
		return
	}
	defer cleanup()

	if _, err := instance.Recover(ctx); err != nil {
		s.log.Warn("journal recovery did not complete",
			slog.String("event", "service.recovery.failed"),
			slog.String("error", err.Error()))
	}

	result, err := instance.Down(ctx)
	if err != nil {
		s.log.Warn("leftover state could not be removed",
			slog.String("event", "service.recovery.failed"),
			slog.String("error", err.Error()))
		return
	}
	for _, removed := range result.Removed {
		s.log.Info("removed an interface left by an earlier run",
			slog.String("event", "service.recovered"),
			slog.String("interface", removed))
	}
}

// runServe is the service entry point.
func runServe(args []string, stdout, stderr *output) int {
	cfg, path, code := loadServeFlags(args, stderr)
	if code != exitOK {
		return code
	}

	identity, err := loadIdentity(cfg)
	if err != nil {
		stderr.printf("nostmesh serve: %v\n", err)
		return exitError
	}

	logger := newLogger(cfg, stderr)

	svc := &service{
		cfg:      cfg,
		log:      logger,
		self:     identity.PublicKey(),
		config:   path,
		workers:  make(map[domain.NostrPublicKey]*peerWorker),
		answered: orchestrator.NewAnsweredSessions(time.Now),
	}

	return svc.run(stdout)
}

// run supervises workers until asked to stop.
func (s *service) run(stdout *output) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGHUP reloads; SIGINT and SIGTERM stop. Separating them is what lets an
	// operator change the allowlist without dropping healthy tunnels.
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	s.log.Info("service starting",
		slog.String("event", "service.started"),
		slog.String("node", s.self.Short()),
		slog.Int("relays", len(s.cfg.Node.Relays)))

	// The control socket lets `nostmesh state` see live sessions. It is opened
	// after the log line above so a failure to open is attributable, and its
	// absence is not fatal: a node that cannot be inspected is worse than one
	// that cannot be inspected remotely, but it still holds its tunnels.
	if listener, err := listenControl(controlSocketPath(s.cfg.Node.StateDir)); err != nil {
		s.log.Warn("state cannot be inspected while this runs",
			slog.String("event", "control.unavailable"),
			slog.String("error", err.Error()))
	} else {
		defer func() { _ = listener.Close() }()
		go serveControl(listener, s.snapshot)
	}

	stdout.printf("nostmesh serving as %s; press Ctrl-C to stop\n", s.self.Short())

	// A previous run that was killed leaves its interface behind, and that
	// interface holds the listen port. Nothing in the journal records it —
	// the transaction committed — so recovery has to look at the host. A
	// starting service holds no sessions, so an interface it finds is residue
	// by definition. Only one this node owns is touched.
	s.recoverHostState(ctx)

	if err := s.reconcile(ctx, s.cfg); err != nil {
		s.log.Error("initial peers could not be started",
			slog.String("event", "service.start.failed"),
			slog.String("error", err.Error()))
		return exitError
	}

	for {
		select {
		case <-ctx.Done():
			s.stopAll()
			return exitOK

		case received := <-signals:
			if received == syscall.SIGHUP {
				s.reload(ctx)
				continue
			}

			s.log.Info("service stopping",
				slog.String("event", "service.stopping"),
				slog.String("signal", received.String()))
			cancel()
			s.stopAll()
			stdout.printf("stopped\n")
			return exitOK
		}
	}
}

// reload re-reads the configuration and applies the difference.
//
// An invalid configuration is reported and discarded. A service that failed
// open here would lose its allowlist to a typo, which is the one outcome worse
// than refusing to reload.
func (s *service) reload(ctx context.Context) {
	cfg, err := config.Load(s.config)
	if err != nil {
		s.log.Error("configuration was not reloaded",
			slog.String("event", "config.reload.failed"),
			slog.String("error", err.Error()))
		return
	}

	// Node-level settings are not reloadable: swapping a bound port or a relay
	// set under running sessions is a different problem, and pretending to
	// support it would be worse than refusing.
	if changed := nodeSettingsChanged(s.cfg, cfg); len(changed) > 0 {
		s.log.Warn("node settings changed but need a restart to take effect",
			slog.String("event", "config.reload.ignored"),
			slog.Any("fields", changed))
	}

	if err := s.reconcile(ctx, cfg); err != nil {
		s.log.Error("configuration was not reloaded",
			slog.String("event", "config.reload.failed"),
			slog.String("error", err.Error()))
		return
	}

	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// reconcile starts workers for newly authorized peers and stops revoked ones.
func (s *service) reconcile(ctx context.Context, cfg config.Config) error {
	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		return err
	}

	wanted := make(map[domain.NostrPublicKey]policy.Grant)
	for _, grant := range allowlist.Grants() {
		if allowlist.Check(grant.Peer, policy.ActionSession) != nil {
			// Revoked, or not granted a session. Either way this node will not
			// hold one with it.
			continue
		}
		wanted[grant.Peer] = grant
	}

	s.mu.Lock()
	running := make(map[domain.NostrPublicKey]*peerWorker, len(s.workers))
	for peer, worker := range s.workers {
		running[peer] = worker
	}
	s.mu.Unlock()

	var started, stopped int

	// Stop first. A revoked peer must lose its worker before anything else
	// happens, so there is no window in which it is still being served.
	for peer, worker := range running {
		if _, keep := wanted[peer]; keep {
			continue
		}
		s.stop(peer, worker, "revoked")
		stopped++
	}

	for peer, grant := range wanted {
		if _, already := running[peer]; already {
			// A healthy tunnel is left alone: reloading must not disturb what
			// it did not change.
			continue
		}
		s.start(ctx, cfg, peer, grant)
		started++
	}

	s.log.Info("configuration applied",
		slog.String("event", "config.reloaded"),
		slog.Int("started", started),
		slog.Int("stopped", stopped),
		slog.Int("running", len(wanted)))

	return nil
}

// start launches a worker for one peer.
func (s *service) start(ctx context.Context, cfg config.Config, peer domain.NostrPublicKey, grant policy.Grant) {
	workerCtx, cancel := context.WithCancel(ctx)

	worker := &peerWorker{
		peer:   peer,
		alias:  grant.Alias,
		cancel: cancel,
		done:   make(chan struct{}),
		log: s.log.With(
			slog.String("peer", peer.Short()),
			slog.String("alias", grant.Alias)),
	}

	s.mu.Lock()
	s.workers[peer] = worker
	s.mu.Unlock()

	worker.log.Info("peer authorized",
		slog.String("event", "peer.added"),
		slog.Any("actions", actionNames(grant.Actions)))

	go worker.run(workerCtx, cfg, s.answered)
}

// stop tears a worker down and waits for it to exit.
func (s *service) stop(peer domain.NostrPublicKey, worker *peerWorker, reason string) {
	// Deregistered before cancelling, so nothing can route to a peer this node
	// has stopped serving.
	s.mu.Lock()
	delete(s.workers, peer)
	s.mu.Unlock()

	_, established := worker.hadSession()

	worker.log.Warn("peer authorization withdrawn",
		slog.String("event", "peer.revoked"),
		slog.String("reason", reason),
		slog.Bool("notified", established))

	worker.cancel()
	<-worker.done

	if reason == revokedReason && established {
		s.notifyRevoked(worker)
	}
}

// notices counts revocation notices this service attempted, for tests that must
// confirm the boundary rather than infer it from timing.
func (s *service) notices() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.noticesSent
}

// notifyRevoked tells a peer its authorization ended.
//
// Only a peer that held a session is told, and the boundary is deliberate.
// Sending this distinguishes "I revoked you" from "I am offline" from "I never
// authorized you" — three states an attacker enumerating identities would like
// to tell apart. A peer with an established session already knew it was
// authorized, so the message reveals nothing it did not have. A peer that never
// connected learns something new, and gets silence instead: its attempts then
// fail exactly as they would for an identity that was never listed.
//
// Best effort by design. The peer's own attempts will fail regardless, and a
// failure to deliver this must not delay tearing the session down.
func (s *service) notifyRevoked(worker *peerWorker) {
	s.mu.Lock()
	s.noticesSent++
	s.mu.Unlock()

	session, _ := worker.hadSession()
	if session == "" {
		// Nothing to name. A close that belongs to no conversation would be
		// discarded by the peer anyway.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), revocationNoticeTimeout)
	defer cancel()

	if err := publishRevocation(ctx, s.cfg, worker.peer, session); err != nil {
		worker.log.Warn("the peer was not told its authorization ended",
			slog.String("event", "peer.revoked.notice.failed"),
			slog.String("error", err.Error()))
		return
	}

	worker.log.Info("the peer was told its authorization ended",
		slog.String("event", "peer.revoked.notice"),
		slog.String("reason", string(protocol.ClosePolicy)))
}

const (
	// revokedReason is the reason recorded when policy withdrew a grant, as
	// opposed to the service simply stopping.
	revokedReason = "revoked"

	// revocationNoticeTimeout bounds the courtesy message, which must never
	// hold up a teardown.
	revocationNoticeTimeout = 15 * time.Second
)

// stopAll tears every worker down.
func (s *service) stopAll() {
	s.mu.Lock()
	workers := make(map[domain.NostrPublicKey]*peerWorker, len(s.workers))
	for peer, worker := range s.workers {
		workers[peer] = worker
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for peer, worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.stop(peer, worker, "service stopping")
		}()
	}
	wg.Wait()
}

// run holds a session with one peer for as long as the worker lives.
func (w *peerWorker) run(ctx context.Context, cfg config.Config, answered *orchestrator.AnsweredSessions) {
	defer close(w.done)

	w.log.Info("worker started", slog.String("event", "peer.worker.started"))
	w.observe("starting", "", 0)

	// Both ends are willing to do either job, and resolveRole settles which one
	// normally opens. A responder whose wait ends with nobody having called
	// takes the other role next time: after both sides lose a session at once,
	// each would otherwise return to waiting and neither would ever call.
	role := orchestrator.RoleAuto

	var consecutive int
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			w.log.Info("worker stopped", slog.String("event", "peer.worker.stopped"))
			return
		}

		started := time.Now()
		w.observe("connecting", "", attempt)
		err := w.attempt(ctx, cfg, answered, role)
		role = roleAfter(err)

		switch {
		case ctx.Err() != nil:
			w.log.Info("worker stopped", slog.String("event", "peer.worker.stopped"))
			return

		case errors.Is(err, orchestrator.ErrNoRequest):
			// Nobody called. Not a failure — but waiting the same way again is
			// how two nodes that both dropped sit facing each other forever, so
			// this one calls next time.
			consecutive = 0
			w.observe("connecting", err.Error(), attempt)
			w.log.Info("no peer opened a session; opening one next",
				slog.String("event", "session.waited"),
				slog.String("reason", err.Error()))

		case errors.Is(err, orchestrator.ErrSessionDropped):
			// A session that ran and then died is not a failed attempt. Backing
			// off as though it were would punish a long, healthy session for
			// ending, so the counter starts over and the peer is picked up
			// again promptly.
			consecutive = 0
			w.observe("reconnecting", err.Error(), attempt)
			w.log.Warn("session ended",
				slog.String("event", "session.dropped"),
				slog.Int64("held_ms", time.Since(started).Milliseconds()),
				slog.String("reason", err.Error()))

		case err == nil:
			consecutive = 0
			w.observe("connecting", "", attempt)

		default:
			consecutive++
			w.observe("retrying", err.Error(), attempt)
			w.log.Warn("attempt did not complete",
				slog.String("event", "session.failed"),
				slog.Int("attempt", attempt),
				slog.String("reason", err.Error()))
		}

		select {
		case <-ctx.Done():
			w.log.Info("worker stopped", slog.String("event", "peer.worker.stopped"))
			return
		case <-time.After(retryDelay(consecutive)):
		}
	}
}

// negotiationBound is how long one attempt's negotiation may take.
//
// The worker itself runs for as long as the operator leaves it running, but a
// single negotiation must not: every step of it waits on the peer, and a peer
// that stopped answering mid-negotiation would otherwise hold the attempt open
// forever. Observed between two real hosts, where both ends sat waiting on each
// other with nothing left to send.
//
// It is generous next to the seconds a negotiation needs, because ending one
// early costs a reconnect while ending one late costs nothing but patience.
const negotiationBound = 2 * time.Minute

// roleAfter decides which role to take after an attempt ended.
//
// A responder whose wait ended with nobody having called takes the other role
// next time. resolveRole is a function of the two keys alone, so the
// higher-keyed node is otherwise always the responder — and after both ends
// lose a session at once, each returns to its role and neither ever calls.
//
// Any other outcome goes back to letting the pair decide. Staying the initiator
// would mean never answering a peer that restarted and opened one itself.
func roleAfter(err error) orchestrator.Role {
	if errors.Is(err, orchestrator.ErrNoRequest) {
		return orchestrator.RoleInitiator
	}
	return orchestrator.RoleAuto
}

// attempt builds a runtime and drives one session.
func (w *peerWorker) attempt(ctx context.Context, cfg config.Config,
	answered *orchestrator.AnsweredSessions, role orchestrator.Role,
) error {
	trace := func(line string) {
		w.log.Debug(line, slog.String("event", "session.trace"))
	}

	runtime, err := buildSessionRuntime(ctx, cfg, w.peer, negotiationBound, trace, answered)
	if err != nil {
		return err
	}
	defer runtime.cleanup()

	go runtime.set.Supervise(ctx)
	go runtime.set.Poll(ctx)

	if err := runtime.driver.Connect(ctx, w.peer, role); err != nil {
		return err
	}

	// Recorded before the hold, not after it. A worker cancelled while holding
	// returns through the cancellation path, and a revocation notice is owed to
	// exactly the peers that reached this point — deferring it until the hold
	// ends would withhold it from every one of them.
	w.recordEstablished()
	w.recordSession(runtime.driver.SessionID(w.peer))

	// Holding is the point. Connect returning means the tunnel works, not that
	// the work is over: leaving now would release the port to a peer that is
	// still using it, and the next attempt would fail to bind against the
	// interface this one just brought up.
	//
	// The relays stay connected for the same reason they were opened — a live
	// session still has a control plane, and roaming and an inbound close both
	// arrive through it.
	err = runtime.driver.Hold(ctx, w.peer, w.observeHold)

	// The interface outlives the runtime and holds the listen port, so it has
	// to go before anything tries to bind again. This runs on cancellation too:
	// a service that stopped while leaving the port claimed is the same residue
	// by another name.
	if releaseErr := runtime.driver.Release(ctx, w.peer); releaseErr != nil {
		w.log.Warn("could not release the session",
			slog.String("event", "session.release.failed"),
			slog.String("reason", releaseErr.Error()))
	}
	return err
}

// snapshot reports what every worker knows, for the control socket.
func (s *service) snapshot() controlState {
	s.mu.Lock()
	workers := make([]*peerWorker, 0, len(s.workers))
	for _, worker := range s.workers {
		workers = append(workers, worker)
	}
	s.mu.Unlock()

	state := controlState{Node: s.self.Short()}
	for _, worker := range workers {
		state.Peers = append(state.Peers, worker.snapshot())
	}

	sort.Slice(state.Peers, func(i, j int) bool {
		return state.Peers[i].Alias < state.Peers[j].Alias
	})
	return state
}

// serving reports whether a peer currently has a worker.
func (s *service) serving(peer domain.NostrPublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, running := s.workers[peer]
	return running
}

// nodeSettingsChanged names node-level fields that differ between two configs.
func nodeSettingsChanged(before, after config.Config) []string {
	var changed []string

	if before.Node.ListenPort != after.Node.ListenPort {
		changed = append(changed, "listen_port")
	}
	if before.Node.OverlayAddress != after.Node.OverlayAddress {
		changed = append(changed, "overlay_address")
	}
	if before.Node.StateDir != after.Node.StateDir {
		changed = append(changed, "state_dir")
	}
	if !sameStrings(before.Node.Relays, after.Node.Relays) {
		changed = append(changed, "relays")
	}
	return changed
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func actionNames(actions []policy.Action) []string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		names = append(names, string(action))
	}
	return names
}

var errServeUsage = errors.New("serve requires a configuration")

// loadServeFlags parses the service's flags.
func loadServeFlags(args []string, stderr *output) (config.Config, string, int) {
	cfg, path, err := parseServeArgs(args, stderr)
	if err != nil {
		if errors.Is(err, errServeUsage) {
			return config.Config{}, "", exitUsage
		}
		stderr.printf("%v\n", err)
		return config.Config{}, "", exitError
	}
	return cfg, path, exitOK
}

func parseServeArgs(args []string, stderr *output) (config.Config, string, error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh serve --config <path>\n\n" +
			"Hold sessions with every authorized peer, for as long as this runs.\n\n" +
			"Either end may open a session at any time; the pair settles which one\n" +
			"does. Peers are added and revoked by editing the configuration and\n" +
			"sending SIGHUP, which systemd does for 'systemctl reload'.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return config.Config{}, "", errServeUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh serve: --config is required\n")
		return config.Config{}, "", errServeUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return config.Config{}, "", fmt.Errorf("%w", err)
	}
	return cfg, *configPath, nil
}
