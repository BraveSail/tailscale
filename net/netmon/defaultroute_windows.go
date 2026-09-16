// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package netmon

import (
	"errors"

	"golang.org/x/sys/windows"

	"github.com/metacubex/tailscale/util/winipcfg"
)

// underlyingDefaultInterface returns the name of the interface carrying the
// underlying (non-tunnel) default route on Windows. While a userspace TUN
// adapter owns the lowest-metric default route, this picks the best physical
// NIC by running the same metric comparison with every virtual interface type
// excluded (the detection sing-tun uses).
func underlyingDefaultInterface() (string, error) {
	ifs, err := getInterfaces(windows.AF_INET, winipcfg.GAAFlagIncludeAllInterfaces, func(iface *winipcfg.IPAdapterAddresses) bool {
		switch iface.IfType {
		case winipcfg.IfTypeSoftwareLoopback, winipcfg.IfTypePropVirtual:
			return false
		}
		return iface.OperStatus == winipcfg.IfOperStatusUp && iface.Flags&winipcfg.IPAAFlagIpv4Enabled != 0
	})
	if err != nil {
		return "", err
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return "", err
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
		return "", errors.New("netmon: no underlying default route found")
	}
	return bestIface.FriendlyName(), nil
}
