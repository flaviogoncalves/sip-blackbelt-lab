#!/bin/bash
# sip-lab take: one phone registers to the served domain (REGISTER -> 401 -> REGISTER + Authorization -> 200).
#   sudo ./take-reg.sh <name> [user, default 2001]
set -u
NAME=$1; USER=${2:-2001}
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp port 5060' 2>/dev/null & TCPD=$!; sleep 1
sipp 192.0.2.10:5060 -sf scenarios/reg.xml -s "$USER" -auth_uri lab.sip -au "$USER" -ap "lab-$USER-pass" \
  -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > captures/$NAME.sipp.log 2>&1 || echo "register failed"
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt
