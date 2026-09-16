// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package netmon

import (
	"errors"

	"github.com/sagernet/netlink"
)

// underlyingDefaultInterface returns the name of the interface carrying the
// underlying (non-VPN) default route on Android, mirroring the detection
// sing-tun uses: walk the ip rules past the VPN rules (uidrange rules
// installed while a VPN is up), take the non-VPN default rule's table, and
// resolve the interface of its first route. While a VPN tunnel owns the
// top-priority rules, this still names the physical NIC carrying data.
func underlyingDefaultInterface() (string, error) {
	ruleList, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return "", err
	}
	var defaultTableIndex int
	for _, rule := range ruleList {
		if rule.Mask == 0x20000 {
			// Android VPN rule (uidrange); keep looking below it.
			continue
		}
		if rule.Mask == 0xFFFF {
			defaultTableIndex = rule.Table
			break
		}
	}
	if defaultTableIndex == 0 {
		return "", errors.New("netmon: no default rule in the routing policy database")
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: defaultTableIndex}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", errors.New("netmon: no route in default table")
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}
