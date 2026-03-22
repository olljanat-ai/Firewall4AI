#!/bin/bash
# Firewall4AI network hardening rules
# Transparent proxy: all HTTP/HTTPS from agents is intercepted automatically.
# Agents do NOT need proxy configuration - iptables redirects their traffic.

INTERNAL_IF=eth1
EXTERNAL_IF=eth0
INTERNAL_NET=10.255.255.0/24
PROXY_IP=10.255.255.1
PROXY_PORT=8080
TRANSPARENT_TLS_PORT=8443
ADMIN_PORT=443

# ============================================================
# Enable IP forwarding (needed for NAT of proxy's outbound)
# ============================================================
echo 1 > /proc/sys/net/ipv4/ip_forward

# ============================================================
# Flush existing rules
# ============================================================
iptables -F
iptables -t nat -F
iptables -X

# ============================================================
# Default policies
# ============================================================
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ============================================================
# Loopback: allow all
# ============================================================
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# ============================================================
# Allow established/related connections
# ============================================================
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# ============================================================
# INPUT rules for the external interface (eth0): allow all
# ============================================================
iptables -A INPUT -i eth0 -j ACCEPT

# ============================================================
# INPUT rules for the internal interface (eth1)
# ============================================================

# Allow DHCP (clients requesting addresses)
iptables -A INPUT -i $INTERNAL_IF -p udp --dport 67 -j ACCEPT

# Allow DNS (dnsmasq)
iptables -A INPUT -i $INTERNAL_IF -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i $INTERNAL_IF -p tcp --dport 53 -j ACCEPT

# Allow proxy connections from internal network (explicit proxy mode)
iptables -A INPUT -i $INTERNAL_IF -s $INTERNAL_NET -p tcp --dport $PROXY_PORT -j ACCEPT

# Allow transparent TLS connections (redirected from port 443)
iptables -A INPUT -i $INTERNAL_IF -s $INTERNAL_NET -p tcp --dport $TRANSPARENT_TLS_PORT -j ACCEPT

# Allow ICMP (ping) from internal network for diagnostics
iptables -A INPUT -i $INTERNAL_IF -p icmp -j ACCEPT

# Reject everything else from internal network
iptables -A INPUT -i $INTERNAL_IF -j REJECT

# ============================================================
# FORWARD rules: reject ALL forwarding from internal network
# Agents cannot route through this host to reach the internet.
# All traffic is intercepted by the transparent proxy.
# ============================================================
iptables -A FORWARD -i $INTERNAL_IF -j REJECT

# ============================================================
# FORWARD rules: accept ALL forwarding from external network
# to allow troubleshooting and diagnostics from the host to
# agent VMs.
# ============================================================
iptables -A FORWARD -i $EXTERNAL_IF -j ACCEPT

# ============================================================
# NAT: Transparent proxy redirect rules
# Intercept HTTP (80) and HTTPS (443) from agent network and
# redirect to the local proxy. Agents need no proxy config.
# ============================================================

# Redirect HTTP to proxy server (transparent HTTP)
iptables -t nat -A PREROUTING -i $INTERNAL_IF -p tcp --dport 80 -j REDIRECT --to-port $PROXY_PORT

# Redirect HTTPS to transparent TLS interceptor
iptables -t nat -A PREROUTING -i $INTERNAL_IF -p tcp --dport 443 -j REDIRECT --to-port $TRANSPARENT_TLS_PORT

# ============================================================
# NAT: masquerade proxy's outbound connections via eth0
# ============================================================
iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE

echo "Firewall4AI iptables rules applied (transparent proxy mode)"
