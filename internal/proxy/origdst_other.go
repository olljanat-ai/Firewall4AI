//go:build !linux

// origdst_other.go stubs the netfilter destination lookup on platforms that
// have no iptables REDIRECT, so the package still builds there. Transparent
// interception is a Linux-only deployment mode.

package proxy

import (
	"errors"
	"net"
)

// originalDestination is not available outside Linux.
func originalDestination(net.Conn) (string, error) {
	return "", errors.New("original destination lookup is only supported on Linux")
}
