package main

import (
	"io"
	"log/slog"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/observability"
)

// newLogger builds the service's logger from configuration.
//
// It writes to stderr and lets the supervisor capture it. systemd already puts
// stderr in the journal with the unit, pid and timestamps attached, so
// `journalctl -u nostmesh` works with no journald-specific code — which matters
// because the binary also has to run where there is no journal at all.
//
// A configured file receives a copy. The returned closer is never nil, so a
// caller can defer it without checking.
func newLogger(cfg config.Config, stderr *output) (*slog.Logger, io.Closer, error) {
	return observability.New(observability.Options{
		Level:    observability.ParseLevel(cfg.Log.Level),
		Format:   cfg.Log.Format,
		FilePath: cfg.Log.File,
	}, stderr.w)
}
