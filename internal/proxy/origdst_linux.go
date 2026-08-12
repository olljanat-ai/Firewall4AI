// origdst_linux.go recovers the destination address a client originally
// connected to, before an iptables REDIRECT rule rewrote it to one of the
// proxy's own listeners. It is what makes HTTPS requests to a bare IP address
// work: such clients send no SNI, so the kernel's connection tracking is the
// only place the real destination still exists.

package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// originalDestination returns the pre-DNAT destination ("host:port") of a
// connection redirected by iptables.
func originalDestination(conn net.Conn) (string, error) {
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return "", errors.New("connection does not expose a file descriptor")
	}
	raw, err := sysConn.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("syscall conn: %w", err)
	}

	ipv6 := isIPv6Conn(conn)
	var addr string
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		addr, sockErr = getOriginalDst(int(fd), ipv6)
	}); err != nil {
		return "", fmt.Errorf("control socket: %w", err)
	}
	return addr, sockErr
}

// isIPv6Conn reports whether the socket is a native IPv6 socket, which is
// answered by the IPv6 netfilter module instead of the IPv4 one. Sockets
// holding an IPv4-mapped address (::ffff:1.2.3.4) are IPv4 connections and
// must be queried on SOL_IP.
func isIPv6Conn(conn net.Conn) bool {
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	return local.IP.To4() == nil
}

// getOriginalDst asks netfilter for the destination the connection carried
// before it was redirected.
func getOriginalDst(fd int, ipv6 bool) (string, error) {
	if ipv6 {
		info, err := unix.GetsockoptIPv6MTUInfo(fd, unix.SOL_IPV6, unix.SO_ORIGINAL_DST)
		if err != nil {
			return "", fmt.Errorf("getsockopt IP6T_SO_ORIGINAL_DST: %w", err)
		}
		ip := net.IP(info.Addr.Addr[:])
		return joinIPPort(ip, portFromNetworkOrder(info.Addr.Port))
	}

	// The IPv4 option returns a struct sockaddr_in: family (2 bytes), port in
	// network byte order (2 bytes), address (4 bytes). IPv6Mreq is simply a
	// large enough buffer to receive it.
	mreq, err := unix.GetsockoptIPv6Mreq(fd, unix.SOL_IP, unix.SO_ORIGINAL_DST)
	if err != nil {
		return "", fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", err)
	}
	raw := mreq.Multiaddr
	ip := net.IPv4(raw[4], raw[5], raw[6], raw[7])
	port := int(raw[2])<<8 | int(raw[3])
	return joinIPPort(ip, port)
}

// portFromNetworkOrder converts a port stored in network byte order, as the
// kernel fills it into a raw sockaddr, into host order.
func portFromNetworkOrder(port uint16) int {
	return int(port>>8) | int(port&0xff)<<8
}

// joinIPPort validates the recovered address and formats it as "host:port".
func joinIPPort(ip net.IP, port int) (string, error) {
	if ip.IsUnspecified() || port == 0 {
		return "", errors.New("no original destination for this connection")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
