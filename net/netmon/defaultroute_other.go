// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android && !windows

package netmon

// underlyingDefaultInterface is Android-only (see defaultroute_android.go).
// On other platforms it reports no result so the caller silently moves on to
// the socket route probe in defaultroute_filter.go.
func underlyingDefaultInterface() (string, string, error) {
	return "", "", nil
}
