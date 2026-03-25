//go:build !linux

package dhcp

// bindToDevice is a no-op on non-Linux platforms.
func bindToDevice(fd uintptr, iface string) {}
