#!/bin/bash
# sip-lab take for lesson 1.1: a call that loses the ACK to the 200 OK. The callee advertises an unreachable Contact,
# retransmits the 200 on Timer A/B spacing and sends BYE at Timer H (about 32 s). Writes captures/<name>.pcap + .txt.
#   sudo ./take-drop.sh <name>
set -u
NAME=$1
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp port 5060' 2>/dev/null & TCPD=$!; sleep 1
S=scenarios
# 2002 registers, then answers the call but never sees the ACK
sipp 192.0.2.10:5060 -sf $S/reg.xml -s 2002 -auth_uri lab.sip -au 2002 -ap lab-2002-pass \
  -i 192.0.2.22 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg 2002 failed"
timeout 45s sipp -sf $S/lostack-uas.xml -s 2002 -i 192.0.2.22 -p 5060 -mp 40000 -m 1 -max_retrans 100 -timeout 45s -nostdin > captures/$NAME.uas.log 2>&1 & UAS=$!
sleep 1
# 2001 registers and calls, handles the 407, then never ACKs the 200
sipp 192.0.2.10:5060 -sf $S/reg.xml -s 2001 -auth_uri lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg 2001 failed"
timeout 45s sipp 192.0.2.10:5060 -sf $S/lostack-uac.xml -s 2001 -set callee 2002 -auth_uri 2002@lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.21 -p 5060 -mp 30000 -m 1 -timeout 45s -nostdin > captures/$NAME.uac.log 2>&1 || echo "call failed"
wait $UAS 2>/dev/null
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt
