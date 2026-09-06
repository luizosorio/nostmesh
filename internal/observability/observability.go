// Package observability builds the node's logger.
//
// Logs go to the system log always, and to a file as well when one is
// configured. The system log needs no code here: the service writes to stderr
// and the supervisor captures it, which is why `journalctl -u nostmesh` works
// with nothing journald-specific in the binary — and why the same binary logs
// correctly on a host that has no journal at all.
//
// See NM-22 for the decision and the rules on what may be logged.
package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format names a log encoding.
const (
	// FormatJSON is the default: logs are meant to be machine-readable.
	FormatJSON = "json"

	// FormatText is for a person reading a terminal.
	FormatText = "text"
)

// fileMode keeps the log readable only by the user that wrote it.
//
// The systemd unit already forces this through UMask, but a umask can only take
// permissions away and the binary also runs outside systemd. Stating the mode
// here is what makes the file safe in both cases — the same reasoning the
// control socket applies to itself.
const fileMode = 0o600

// Options is the resolved logging configuration.
type Options struct {
	// Level is the minimum severity that reaches a sink.
	Level slog.Level

	// Format is FormatJSON or FormatText.
	Format string

	// FilePath is an optional second sink. Empty means the system log only.
	FilePath string
}

// New builds the logger and returns a closer for the file sink.
//
// The closer is never nil, so a caller can defer it without a check. It closes
// the file if there is one and does nothing otherwise.
func New(opts Options, stderr io.Writer) (*slog.Logger, io.Closer, error) {
	writer := stderr
	closer := io.Closer(noopCloser{})

	if opts.FilePath != "" {
		file, err := openLogFile(opts.FilePath)
		if err != nil {
			// Refused rather than degraded to stderr alone. An operator who
			// configured a log file and got no error believes they have an
			// audit trail; leaving them with one that was never written is
			// worse than failing to start where the cause is still visible.
			return nil, nil, err
		}

		// The file is wrapped so its failures stay its own.
		//
		// io.MultiWriter writes in order and returns at the first error, so a
		// sink that fails takes down every sink after it. Today the system log
		// is written first and would survive on ordering alone — but that makes
		// a property the operator depends on into an accident of argument
		// order, which the next person to add a sink has no reason to preserve.
		// The wrapper states it instead: a copy on disk never costs the sink
		// the operator is guaranteed to have.
		writer = io.MultiWriter(stderr, &tolerantWriter{w: file})
		closer = file
	}

	handlerOptions := &slog.HandlerOptions{Level: opts.Level}

	if strings.EqualFold(opts.Format, FormatText) {
		return slog.New(slog.NewTextHandler(writer, handlerOptions)), closer, nil
	}
	return slog.New(slog.NewJSONHandler(writer, handlerOptions)), closer, nil
}

// openLogFile opens the file sink for appending.
func openLogFile(path string) (*os.File, error) {
	// The path is operator-supplied configuration, and validation has already
	// refused a relative one.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode) //nolint:gosec // operator-supplied path by design
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", path, err)
	}
	return file, nil
}

// Discard returns a logger that drops everything.
//
// It is the default for every constructor that takes an optional logger, so a
// package that was never given one logs nothing rather than needing a nil check
// at each call site.
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// Component returns a child logger tagged with the component that emits it.
//
// Every line carries this: a log that says a handshake failed without saying
// which layer observed the failure sends its reader to the wrong place.
func Component(log *slog.Logger, name string) *slog.Logger {
	if log == nil {
		return Discard()
	}
	return log.With(slog.String("component", name))
}

// Component names, so a filter is written against a constant rather than a
// string that might be spelled differently in two places.
const (
	ComponentService      = "service"
	ComponentNostr        = "nostr"
	ComponentSession      = "session"
	ComponentConnectivity = "connectivity"
	ComponentWireGuard    = "wireguard"
	ComponentNetstate     = "netstate"
)

// ParseLevel maps a configured level name, defaulting to info.
//
// An unrecognised name takes the default rather than failing: losing every log
// line because of a typo in one field is worse than logging more than asked.
// Configuration validation reports the typo separately.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// noopCloser stands in when there is no file to close.
type noopCloser struct{}

func (noopCloser) Close() error { return nil }
