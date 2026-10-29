#!/bin/bash
# sip-lab take for lesson 2.4 with baresip: the account says wrong.sip, which the registrar does not serve -> 404.
#   sudo ./take-wrongdomain-baresip.sh <name>
set -u
NAME=$1
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
grep -q "wrong.sip" /etc/hosts || echo "192.0.2.10 wrong.sip" >> /etc/hosts
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp port 5060' 2>/dev/null & TCPD=$!; sleep 1
D=$(./baresip-conf.sh 2001wrong 192.0.2.21 2001 2001 lab-2001-pass wrong.sip)
timeout 6 baresip -f "$D" -t 6 -s > captures/$NAME.baresip.log 2>&1 || true
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt
