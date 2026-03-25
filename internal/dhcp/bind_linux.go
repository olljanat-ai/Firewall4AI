//go:build linux

package dhcp

import "syscall"

// bindToDevice binds a socket to a specific network interface using SO_BINDTODEVICE.
func bindToDevice(fd uintptr, iface string) {
	syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}
