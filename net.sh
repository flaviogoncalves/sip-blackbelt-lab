#!/bin/sh
# sip-lab addresses from the documentation range (RFC 5737), so traces need no masking:
# 192.0.2.10 = lab.sip (OpenSIPS) on lab0; phones 2001/2002/2003 = 192.0.2.21/.22/.23, each on its own dummy interface
# (lab21, lab22, lab23) so baresip's net_interface gives it its own address for SDP and RTP instead of the public one.
set -e
dummy() {  # dummy <ifname> <last octet>
  ip link show "$1" >/dev/null 2>&1 || ip link add "$1" type dummy
  ip link set "$1" up
  ip addr show dev "$1" | grep -q "192.0.2.$2/" || ip addr add "192.0.2.$2/32" dev "$1"
}
dummy lab0 10
for a in 21 22 23; do
  ip addr del "192.0.2.$a/24" dev lab0 2>/dev/null || true   # older boxes had every address on lab0
  dummy "lab$a" "$a"
done
ip route show | grep -q "^192.0.2.0/24" || ip route add 192.0.2.0/24 dev lab0
# baresip binds RTP to 0.0.0.0, so on this one box the kernel would stamp a phone's RTP with the destination's address.
# Give each phone's RTP range its own source address, as separate hosts would (2001: 30000-30009, 2002: 40000-40009,
# 2003 or a second 2002 phone on .23: 50000-50009).
for r in "30000:30009 192.0.2.21" "40000:40009 192.0.2.22" "50000:50009 192.0.2.23"; do   # iptables comes with ufw
  set -- $r
  # only toward the lab's addresses: a dig to 127.0.0.1 from a port in the range was stamped 192.0.2.23 (2026-10-28)
  iptables -t nat -C POSTROUTING -p udp -d 192.0.2.0/24 --sport "$1" -j SNAT --to-source "$2" 2>/dev/null ||
    iptables -t nat -A POSTROUTING -p udp -d 192.0.2.0/24 --sport "$1" -j SNAT --to-source "$2"
done
# a socket already bound to its phone's address (SIPp) needs no rewrite: leave it untracked, or its conntrack entry
# collides with the other phone's rewritten reply and the kernel moves that reply to a random source port
for r in "30000:30009 192.0.2.21" "40000:40009 192.0.2.22" "50000:50009 192.0.2.23"; do
  set -- $r
  iptables -t raw -C OUTPUT -p udp -s "$2" --sport "$1" -j NOTRACK 2>/dev/null ||
    iptables -t raw -A OUTPUT -p udp -s "$2" --sport "$1" -j NOTRACK
done
grep -q "lab.sip" /etc/hosts || echo "192.0.2.10 lab.sip" >> /etc/hosts
ip -br addr show | grep "^lab"
