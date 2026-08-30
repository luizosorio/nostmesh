//go:build linux

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// defaultMTU leaves room for the WireGuard header inside a 1500-byte path.
const defaultMTU = 1420

// LinuxAdapter configures WireGuard through netlink.
//
// Per NM-05 it never invokes wg, wg-quick or ip: every change goes through a
// typed netlink call, so failures are structured values rather than parsed
// text.
type LinuxAdapter struct {
	client *wgctrl.Client
}

// NewLinuxAdapter opens a WireGuard control client.
func NewLinuxAdapter() (*LinuxAdapter, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("opening wireguard control socket: %w", err)
	}
	return &LinuxAdapter{client: client}, nil
}

// Close releases the control client.
func (a *LinuxAdapter) Close() error {
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// EnsureInterface brings the interface to the desired state.
//
// It is idempotent: an interface that already matches is left alone, and one
// that partially matches is corrected. Re-running after an interrupted apply
// converges rather than failing.
func (a *LinuxAdapter) EnsureInterface(ctx context.Context, spec InterfaceSpec) (InterfaceState, error) {
	if !OwnsInterface(spec.Name) {
		return InterfaceState{}, fmt.Errorf("%w: interface %q does not carry the %q prefix",
			ErrNotOwned, spec.Name, InterfacePrefix)
	}
	if err := ctx.Err(); err != nil {
		return InterfaceState{}, err
	}

	link, err := a.ensureLink(spec.Name)
	if err != nil {
		return InterfaceState{}, err
	}
	if err := a.configureDevice(spec); err != nil {
		return InterfaceState{}, err
	}
	if err := a.ensureAddresses(link, spec.Addresses); err != nil {
		return InterfaceState{}, err
	}

	mtu := spec.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return InterfaceState{}, fmt.Errorf("setting MTU on %s: %w", spec.Name, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return InterfaceState{}, fmt.Errorf("bringing up %s: %w", spec.Name, err)
	}

	return a.ObserveInterface(ctx, spec.Name)
}

// ensureLink returns the interface, creating it if absent.
func (a *LinuxAdapter) ensureLink(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		if link.Type() != "wireguard" {
			return nil, fmt.Errorf("%w: %s exists but is a %s interface", ErrNotOwned, name, link.Type())
		}
		return link, nil
	}

	var notFound netlink.LinkNotFoundError
	if !errors.As(err, &notFound) {
		return nil, fmt.Errorf("looking up %s: %w", name, err)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		return nil, fmt.Errorf("creating %s: %w", name, err)
	}

	link, err = netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("looking up %s after creating it: %w", name, err)
	}
	return link, nil
}

// configureDevice sets the interface's private key and listen port.
func (a *LinuxAdapter) configureDevice(spec InterfaceSpec) error {
	raw, err := spec.PrivateKey.Bytes()
	if err != nil {
		return fmt.Errorf("configuring %s: %w", spec.Name, err)
	}
	defer zero(raw)

	key, err := wgtypes.NewKey(raw)
	if err != nil {
		return fmt.Errorf("configuring %s: %w", spec.Name, err)
	}

	config := wgtypes.Config{PrivateKey: &key}
	if spec.ListenPort > 0 {
		port := spec.ListenPort
		config.ListenPort = &port
	}

	if err := a.client.ConfigureDevice(spec.Name, config); err != nil {
		return fmt.Errorf("configuring %s: %w", spec.Name, err)
	}
	return nil
}

// ensureAddresses adds missing addresses and removes ones no longer wanted.
//
// Only addresses on a NostMesh interface are touched, and the interface itself
// was verified as ours before this runs.
func (a *LinuxAdapter) ensureAddresses(link netlink.Link, wanted []netip.Prefix) error {
	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("listing addresses on %s: %w", link.Attrs().Name, err)
	}

	present := make(map[string]netlink.Addr, len(existing))
	for _, addr := range existing {
		if addr.IP.IsLinkLocalUnicast() {
			// The kernel adds link-local addresses on its own; they are not
			// ours to manage.
			continue
		}
		present[addr.IPNet.String()] = addr
	}

	for _, prefix := range wanted {
		parsed, err := netlink.ParseAddr(prefix.String())
		if err != nil {
			return fmt.Errorf("parsing address %s: %w", prefix, err)
		}
		if _, ok := present[parsed.IPNet.String()]; ok {
			delete(present, parsed.IPNet.String())
			continue
		}
		if err := netlink.AddrAdd(link, parsed); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("adding address %s to %s: %w", prefix, link.Attrs().Name, err)
		}
		delete(present, parsed.IPNet.String())
	}

	for _, stale := range present {
		if err := netlink.AddrDel(link, &stale); err != nil {
			return fmt.Errorf("removing address %s from %s: %w", stale.IPNet, link.Attrs().Name, err)
		}
	}
	return nil
}

// ApplyPeer brings one peer to the desired state.
func (a *LinuxAdapter) ApplyPeer(ctx context.Context, iface string, spec PeerSpec) error {
	if !OwnsInterface(iface) {
		return fmt.Errorf("%w: %s", ErrNotOwned, iface)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	key, err := wgtypes.NewKey(spec.PublicKey[:])
	if err != nil {
		return fmt.Errorf("applying peer to %s: %w", iface, err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey: key,
		// Replace rather than merge: AllowedIPs are derived from local policy,
		// so the computed set is the whole truth. Merging would let a stale
		// entry from an earlier configuration survive a policy change.
		ReplaceAllowedIPs: true,
		AllowedIPs:        toIPNets(spec.AllowedIPs),
	}

	if spec.Endpoint != nil {
		peer.Endpoint = &net.UDPAddr{
			IP:   spec.Endpoint.Addr().AsSlice(),
			Port: int(spec.Endpoint.Port()),
		}
	}
	if spec.PersistentKeepalive > 0 {
		keepalive := spec.PersistentKeepalive
		peer.PersistentKeepaliveInterval = &keepalive
	}

	if err := a.client.ConfigureDevice(iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}}); err != nil {
		return fmt.Errorf("applying peer %s to %s: %w", spec.PublicKey.Short(), iface, err)
	}
	return nil
}

// RemovePeer removes a peer. Removing an absent peer is not an error, so
// compensation can run without first checking.
func (a *LinuxAdapter) RemovePeer(ctx context.Context, iface string, publicKey domain.WireGuardPublicKey) error {
	if !OwnsInterface(iface) {
		return fmt.Errorf("%w: %s", ErrNotOwned, iface)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	key, err := wgtypes.NewKey(publicKey[:])
	if err != nil {
		return fmt.Errorf("removing peer from %s: %w", iface, err)
	}

	config := wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}}
	if err := a.client.ConfigureDevice(iface, config); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("removing peer %s from %s: %w", publicKey.Short(), iface, err)
	}
	return nil
}

// ObserveInterface reports what the kernel says about an interface.
func (a *LinuxAdapter) ObserveInterface(ctx context.Context, iface string) (InterfaceState, error) {
	if err := ctx.Err(); err != nil {
		return InterfaceState{}, err
	}

	device, err := a.client.Device(iface)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return InterfaceState{}, fmt.Errorf("%w: %s", ErrInterfaceNotFound, iface)
		}
		return InterfaceState{}, fmt.Errorf("observing %s: %w", iface, err)
	}

	state := InterfaceState{
		Name:       device.Name,
		ListenPort: device.ListenPort,
		OwnedByUs:  OwnsInterface(device.Name),
	}
	copy(state.PublicKey[:], device.PublicKey[:])

	link, err := netlink.LinkByName(iface)
	if err == nil {
		state.MTU = link.Attrs().MTU
		state.Addresses = observedAddresses(link)
	}

	for _, peer := range device.Peers {
		state.Peers = append(state.Peers, observedPeer(peer))
	}
	return state, nil
}

func observedAddresses(link netlink.Link) []netip.Prefix {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}

	var prefixes []netip.Prefix
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			continue
		}
		if prefix, ok := netip.AddrFromSlice(addr.IP); ok {
			ones, _ := addr.Mask.Size()
			prefixes = append(prefixes, netip.PrefixFrom(prefix.Unmap(), ones))
		}
	}
	return prefixes
}

func observedPeer(peer wgtypes.Peer) PeerState {
	state := PeerState{
		LastHandshake:       peer.LastHandshakeTime,
		ReceiveBytes:        peer.ReceiveBytes,
		TransmitBytes:       peer.TransmitBytes,
		PersistentKeepalive: peer.PersistentKeepaliveInterval,
	}
	copy(state.PublicKey[:], peer.PublicKey[:])

	if peer.Endpoint != nil {
		// The kernel reports the port as an int, but a UDP port cannot exceed
		// 65535. A value outside that range means the endpoint is not
		// meaningful, so it is dropped rather than silently truncated.
		if addr, ok := netip.AddrFromSlice(peer.Endpoint.IP); ok &&
			peer.Endpoint.Port > 0 && peer.Endpoint.Port <= math.MaxUint16 {
			endpoint := netip.AddrPortFrom(addr.Unmap(), uint16(peer.Endpoint.Port))
			state.Endpoint = &endpoint
		}
	}
	for _, allowed := range peer.AllowedIPs {
		if addr, ok := netip.AddrFromSlice(allowed.IP); ok {
			ones, _ := allowed.Mask.Size()
			state.AllowedIPs = append(state.AllowedIPs, netip.PrefixFrom(addr.Unmap(), ones))
		}
	}
	return state
}

// RemoveInterface deletes an interface NostMesh owns.
//
// The ownership check is the point: an operator may well have other WireGuard
// interfaces, and removing one of those would break their networking with no
// way for NostMesh to restore it.
func (a *LinuxAdapter) RemoveInterface(ctx context.Context, iface string) error {
	if !OwnsInterface(iface) {
		return fmt.Errorf("%w: refusing to remove %s", ErrNotOwned, iface)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("looking up %s: %w", iface, err)
	}

	if link.Type() != "wireguard" {
		return fmt.Errorf("%w: %s is a %s interface", ErrNotOwned, iface, link.Type())
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("removing %s: %w", iface, err)
	}
	return nil
}

func toIPNets(prefixes []netip.Prefix) []net.IPNet {
	nets := make([]net.IPNet, 0, len(prefixes))
	for _, prefix := range prefixes {
		nets = append(nets, net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		})
	}
	return nets
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time confirmation that the adapter satisfies the port.
var _ Controller = (*LinuxAdapter)(nil)
