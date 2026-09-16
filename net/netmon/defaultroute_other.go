// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android && !windows

package netmon

import "errors"

// underlyingDefaultInterface is Android-only (see defaultroute_android.go).
// On other platforms the socket route probe in defaultroute_filter.go remains
// the fallback.
func underlyingDefaultInterface() (string, error) {
	return "", errors.New("netmon: underlying default interface detection not implemented on this platform")
}
