//go:build !linux

package wireguard

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrUnsupportedPlatform reports a platform with no WireGuard adapter.
var ErrUnsupportedPlatform = errors.New("no wireguard adapter for this platform")

// NewController reports that this platform has no adapter yet.
//
// The core compiles everywhere by design (NM-02), so the binary builds on any
// platform; only the commands that touch the data plane are unavailable. That
// keeps the portability guard meaningful: the boundary is verified continuously
// rather than discovered when a port is attempted.
func NewController() (Controller, func() error, error) {
	return nil, func() error { return nil },
		fmt.Errorf("%w: %s; see the roadmap for platform support", ErrUnsupportedPlatform, runtime.GOOS)
}
