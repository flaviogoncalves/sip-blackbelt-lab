#!/bin/bash
# sip-lab take for lesson 2.1: two registrations and the registrar's location table (usrloc:dump).
#   sudo ./take-location.sh <name>
set -u
NAME=$1
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp port 5060' 2>/dev/null & TCPD=$!; sleep 1
for u in 2001 2002; do
  sipp 192.0.2.10:5060 -sf scenarios/reg.xml -s "$u" -auth_uri lab.sip -au "$u" -ap "lab-$u-pass" \
    -i "192.0.2.$([ "$u" = 2001 ] && echo 21 || echo 22)" -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $u failed"
done
opensips-cli -x mi usrloc:dump > captures/$NAME.location.txt 2>&1
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt; echo "=== location ==="; cat captures/$NAME.location.txt
