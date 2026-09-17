// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/tailscale/types/logger"
)

// isTunnelInterface reports whether name looks like a userspace tunnel
// interface (VPN TUN/TAP, WireGuard, PPP). While such an interface is up it
// owns the system default route, which makes route probes resolve to the
// tunnel instead of the physical NIC that actually carries traffic.
func isTunnelInterface(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{"tun", "utun", "tap", "wg", "ppp", "ipsec"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// probeV6Route is an arbitrary globally-routable IPv6 address used to ask the
// kernel which interface a default-route packet would leave from. No packet is
// ever sent: a UDP "connect" only performs a route lookup and binds the socket
// to the selected source address.
const probeV6Route = "[2400:3200::1]:53" // OneDNS public address (CN)

// DefaultRouteInterfaceNameViaSocket finds the name of the interface holding
// the IPv6 default route by performing a route lookup on an unconnected UDP
// socket's local end.
//
// It dials a public IPv6 address (without sending any packets) and asks the
// kernel which source address it would use; the source address is then mapped
// back to its owning interface by name. This works in unprivileged sandboxes
// (e.g. Android app processes) where reading the routing table via netlink or
// /proc is unavailable, and behaves consistently across platforms (Linux,
// Windows, macOS, Android) since it relies only on standard socket semantics.
func DefaultRouteInterfaceNameViaSocket() (string, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("udp6", probeV6Route)
	if err != nil {
		return "", fmt.Errorf("route probe dial: %w", err)
	}
	defer conn.Close()

	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la == nil || la.IP == nil || la.IP.IsUnspecified() {
		return "", fmt.Errorf("route probe: no local socket address")
	}
	src, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return "", fmt.Errorf("route probe: unusable local socket address")
	}
	src = src.Unmap()

	ifaces, err := GetInterfaceList()
	if err != nil {
		return "", fmt.Errorf("route probe: %w", err)
	}
	var found string
	ifaces.ForeachInterface(func(iface Interface, pfxs []netip.Prefix) {
		if found != "" {
			return
		}
		for _, pfx := range pfxs {
			if pfx.Addr() == src {
				found = iface.Name
				return
			}
		}
	})
	if found == "" {
		return "", fmt.Errorf("route probe: no interface owns source %s", src)
	}
	return found, nil
}

// defaultRouteInterfaceName returns the name of the interface holding the
// default route and the strategy that resolved it ("platform",
// "uid-route", "main-table", "rpdb-main-rule" or "socket-probe").
//
// Preference order: the platform route reader (accurate on systems whose
// embedding app keeps it populated), platform-specific underlying-route
// detection (Android/Windows: finds the physical NIC while a VPN tunnel
// owns the top-priority rules), then the socket route probe as a last
// resort — which, while a TUN is up, resolves to the tunnel itself.
//
// A platform result naming a virtual adapter is rejected: on Windows the
// OS default-route lookup returns the VPN's own TUN (a wintun adapter is
// named after the application, so a name check alone cannot spot it).
func defaultRouteInterfaceName(logf logger.Logf) (name string, how string, err error) {
	if ifName, err := DefaultRouteInterface(); err == nil && ifName != "" {
		if !isVirtualInterfaceName(ifName) {
			return ifName, "platform", nil
		}
		if logf != nil {
			logf("netmon: platform default-route interface %q is virtual; probing for the physical NIC", ifName)
		}
	}
	if ifName, h, err := underlyingDefaultInterface(); err == nil && ifName != "" {
		return ifName, h, nil
	} else if err != nil && logf != nil {
		logf("netmon: underlying default-interface probe failed: %v", err)
	}
	ifName, err := DefaultRouteInterfaceNameViaSocket()
	if err != nil {
		return "", "socket-probe", err
	}
	return ifName, "socket-probe", nil
}

// AddressesOnDefaultRouteInterface filters addrs down to those assigned to the
// interface holding the default route (on a multi-SIM phone, the SIM currently
// carrying data).
//
// The default-route interface is resolved via defaultRouteInterfaceName. When
// it cannot be resolved, or none of the given addresses live on it, addrs is
// returned unchanged: callers degrade to their unfiltered behavior instead of
// losing all addresses.
//
// logf receives the decision trace (nil is allowed and logs nothing); pass the
// caller's logger so the outcome is visible in the host application's log view
// rather than the process stderr.
func AddressesOnDefaultRouteInterface(logf logger.Logf, addrs []netip.Addr) []netip.Addr {
	debugf := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
		}
	}
	ifName, how, err := defaultRouteInterfaceName(debugf)
	if err != nil || ifName == "" {
		debugf("netmon: default-route interface unresolved (via=%s, err=%v); keeping all %d addresses", how, err, len(addrs))
		return addrs
	}
	if isVirtualInterfaceName(ifName) {
		// A VPN tunnel owns the system default route while it is up, so the
		// route probe resolves to the tunnel itself — not the NIC actually
		// carrying data. Filtering by the tunnel would drop every real
		// address (kept 0), so keep the physical-interface addresses instead
		// (drop only addresses owned by virtual interfaces).
		kept := keepPhysicalAddrs(addrs)
		if len(kept) == 0 {
			debugf("netmon: default-route interface %q is virtual (via=%s) and no physical addresses remain; keeping all %d addresses", ifName, how, len(addrs))
			return addrs
		}
		debugf("netmon: default-route interface %q is a tunnel (via=%s): kept %d of %d physical addresses", ifName, how, len(kept), len(addrs))
		return kept
	}
	keep := map[netip.Addr]bool{}
	err = ForeachInterface(func(iface Interface, pfxs []netip.Prefix) {
		if iface.Name != ifName {
			return
		}
		for _, pfx := range pfxs {
			keep[pfx.Addr().Unmap()] = true
		}
	})
	if err != nil || len(keep) == 0 {
		debugf("netmon: default-route interface %q has no addresses (via=%s, err=%v); keeping all %d addresses", ifName, how, err, len(addrs))
		return addrs
	}
	out := addrs[:0]
	for _, a := range addrs {
		if keep[a.Unmap()] {
			out = append(out, a)
		}
	}
	debugf("netmon: default-route interface %q (via=%s): kept %d of %d addresses", ifName, how, len(out), len(addrs))
	return out
}

// keepPhysicalAddrs drops addresses owned by virtual interfaces, keeping the
// addresses of physical NICs.
func keepPhysicalAddrs(addrs []netip.Addr) []netip.Addr {
	virtualOwned := map[netip.Addr]bool{}
	_ = ForeachInterface(func(iface Interface, pfxs []netip.Prefix) {
		if !isVirtualInterfaceName(iface.Name) {
			return
		}
		for _, pfx := range pfxs {
			virtualOwned[pfx.Addr().Unmap()] = true
		}
	})
	out := addrs[:0]
	for _, a := range addrs {
		if !virtualOwned[a.Unmap()] {
			out = append(out, a)
		}
	}
	return out
}
