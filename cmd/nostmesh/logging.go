package main

import (
	"log/slog"
	"strings"

	"github.com/luizosorio/nostmesh/internal/config"
)

// newLogger builds the service's logger from configuration.
//
// It writes to stderr and lets the supervisor capture it. systemd already puts
// stderr in the journal with the unit, pid and timestamps attached, so
// `journalctl -u nostmesh` works with no journald-specific code — which matters
// because the binary also has to run where there is no journal at all.
func newLogger(cfg config.Config, stderr *output) *slog.Logger {
	options := &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)}

	if strings.EqualFold(cfg.Log.Format, "text") {
		return slog.New(slog.NewTextHandler(stderr.w, options))
	}
	return slog.New(slog.NewJSONHandler(stderr.w, options))
}

// parseLevel maps the configured level, defaulting to info.
//
// An unrecognised level takes the default rather than failing: losing all logs
// because of a typo in one field is worse than logging more than asked.
func parseLevel(level string) slog.Level {
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
