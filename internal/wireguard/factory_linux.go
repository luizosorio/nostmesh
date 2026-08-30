//go:build linux

package wireguard

// NewController opens the platform's WireGuard controller.
//
// This is the seam that keeps callers platform-neutral: the CLI asks for a
// controller and gets whichever adapter this build has, so adding a platform
// means adding an adapter file, not editing every call site.
func NewController() (Controller, func() error, error) {
	adapter, err := NewLinuxAdapter()
	if err != nil {
		return nil, func() error { return nil }, err
	}
	return adapter, adapter.Close, nil
}
