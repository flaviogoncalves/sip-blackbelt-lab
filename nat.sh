#!/bin/sh
# A real NAT on the sip-lab box for section 4 part B (network namespaces; addresses from RFC 5737 and RFC 1918):
#   home    namespace: phone 2001 at 192.168.1.21 (interface lab21, so baresip-conf.sh's net_interface still fits),
#           default route via the router's LAN side 192.168.1.1
#   router  namespace: lan 192.168.1.1/24, wan 198.51.100.21/24; MASQUERADE out of wan (a home router: it keeps no
#           inbound door open, new connections from the wan side are dropped)
#   root    = the internet side: OpenSIPS 192.0.2.10, phone 2002 192.0.2.22 (net.sh), natwan 198.51.100.1/24 toward the
#           router; 192.168.0.0/16 routes into a dummy interface (labvoid) where packets are seen and go nowhere,
#           as a private address does on the internet
#   nat.sh [up] [preserve|random]   build or rebuild (idempotent); random = the NAT picks a random external port
#                                   (MASQUERADE --random), preserve = it keeps the phone's port when it can (Linux default)
#   nat.sh down                     remove all of it
set -e
R="ip netns exec router"; H="ip netns exec home"
if [ "${1:-up}" = down ]; then
  ip netns del home 2>/dev/null || true
  ip netns del router 2>/dev/null || true   # takes the veth pairs (and natwan) with it
  ip link del natwan 2>/dev/null || true
  ip link del labvoid 2>/dev/null || true
  while iptables -D INPUT -i natwan -j ACCEPT 2>/dev/null; do :; done
  exit 0
fi
MODE=${2:-random}
ip netns list | grep -qw router || ip netns add router
ip netns list | grep -qw home || ip netns add home
ip link show natwan >/dev/null 2>&1 || { ip link add natwan type veth peer name wan; ip link set wan netns router; }
$R ip link show lan >/dev/null 2>&1 || { $R ip link add lan type veth peer name lab21; $R ip link set lab21 netns home; }

# internet side (root namespace)
echo 1 > /proc/sys/net/ipv6/conf/natwan/disable_ipv6
ip addr replace 198.51.100.1/24 dev natwan; ip link set natwan up
# baresip binds RTP to 0.0.0.0: packets toward the NAT leave with phone 2002's address, as from a separate host
ip route replace 198.51.100.0/24 dev natwan src 192.0.2.22
ip link show labvoid >/dev/null 2>&1 || ip link add labvoid type dummy
ip link set labvoid up
ip route replace 192.168.0.0/16 dev labvoid src 192.0.2.22
# ufw drops everything that is not on lo: let the router's traffic in while the lab exists
iptables -C INPUT -i natwan -j ACCEPT 2>/dev/null || iptables -I INPUT -i natwan -j ACCEPT

# the router
$R ip link set lo up
$R sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'   # IPv4 only: no link-local noise in the traces
$R ip addr replace 198.51.100.21/24 dev wan; $R ip link set wan up
$R ip addr replace 192.168.1.1/24 dev lan; $R ip link set lan up
$R ip route replace default via 198.51.100.1
$R sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
$R iptables -t raw -F; $R iptables -t nat -F; $R iptables -F
if [ "$MODE" = random ]; then $R iptables -t nat -A POSTROUTING -o wan -j MASQUERADE --random
else $R iptables -t nat -A POSTROUTING -o wan -j MASQUERADE; fi
$R iptables -A INPUT -i lo -j ACCEPT
$R iptables -A INPUT -i lan -j ACCEPT
$R iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$R iptables -P INPUT DROP
$R iptables -A FORWARD -i lan -o wan -j ACCEPT
$R iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$R iptables -P FORWARD DROP

# the home LAN
$H ip link set lo up
$H sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
$H ip addr replace 192.168.1.21/24 dev lab21; $H ip link set lab21 up
$H ip route replace default via 192.168.1.1
echo "nat: $MODE"; $R ip -br addr; $H ip -br addr
