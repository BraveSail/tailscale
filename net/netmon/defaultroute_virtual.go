// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package netmon

import "strings"

// isVirtualInterfaceName reports whether name belongs to an interface that
// cannot be the physical NIC carrying traffic: the loopback device or a
// userspace tunnel. Windows classifies adapters by type and description
// instead (see defaultroute_windows.go), because a TUN there is named after
// the application that created it.
func isVirtualInterfaceName(name string) bool {
	if name == "" {
		return true
	}
	n := strings.ToLower(name)
	if n == "lo" || strings.HasPrefix(n, "lo") && len(n) > 2 {
		return true
	}
	return isTunnelInterface(n)
}
