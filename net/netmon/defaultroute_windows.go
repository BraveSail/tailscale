// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package netmon

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/metacubex/tailscale/util/winipcfg"
)

// isVirtualInterfaceName reports whether name belongs to an adapter that
// cannot be the physical NIC carrying traffic. A userspace TUN is named after
// the application that created it (FlClash's wintun adapter is "FlClash"), so
// the adapter type and description decide here, not the interface name.
func isVirtualInterfaceName(name string) bool {
	if name == "" {
		return true
	}
	if isTunnelInterface(name) {
		return true
	}
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return false
	}
	for _, iface := range ifs {
		if strings.EqualFold(iface.FriendlyName(), name) {
			return isVirtualAdapter(iface)
		}
	}
	return false
}

// isVirtualAdapter reports whether iface is a loopback, virtual or tunnel
// adapter rather than a physical NIC. wintun adapters (sing-tun, WireGuard and
// friends) are IF_TYPE_PROP_VIRTUAL with a description naming the tunnel.
func isVirtualAdapter(iface *winipcfg.IPAdapterAddresses) bool {
	switch iface.IfType {
	case winipcfg.IfTypeSoftwareLoopback, winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel:
		return true
	}
	desc := strings.ToLower(iface.Description())
	for _, marker := range []string{"wintun", "sing-tun", "tailscale", "wireguard", "tap-windows", "openvpn", "tunnel", "vpn"} {
		if strings.Contains(desc, marker) {
			return true
		}
	}
	return false
}

// underlyingDefaultInterface returns the name of the interface carrying the
// underlying (non-tunnel) default route on Windows. While a userspace TUN
// adapter owns the lowest-metric default route, this picks the best physical
// NIC by running the same metric comparison with every virtual interface type
// excluded (the detection sing-tun uses).
func underlyingDefaultInterface() (string, string, error) {
	ifs, err := getInterfaces(windows.AF_INET, winipcfg.GAAFlagIncludeAllInterfaces, func(iface *winipcfg.IPAdapterAddresses) bool {
		return !isVirtualAdapter(iface) &&
			iface.OperStatus == winipcfg.IfOperStatusUp &&
			iface.Flags&winipcfg.IPAAFlagIpv4Enabled != 0
	})
	if err != nil {
		return "", "", err
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return "", "", err
	}

	bestMetric := ^uint32(0)
	var bestIface *winipcfg.IPAdapterAddresses
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			// Not a default route.
			continue
		}
		iface := ifs[route.InterfaceLUID]
		if iface == nil {
			continue
		}
		ifr, err := route.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}
		// As elsewhere in this package: the effective metric is the route
		// metric plus the interface metric for this address family.
		metric := route.Metric + ifr.Metric
		if metric < bestMetric {
			bestMetric = metric
			bestIface = iface
		}
	}
	if bestIface == nil {
		return "", "", errors.New("netmon: no underlying default route found")
	}
	return bestIface.FriendlyName(), "winipcfg-metric", nil
}
