#!/bin/bash
# One take on sip-lab: OpenSIPS up with lab.cfg, a capture on lo, 2002 registers and answers, 2001 registers and calls.
#   sudo ./take.sh <name> [digest algorithms, e.g. "SHA-256,MD5"; default MD5]
# Writes captures/<name>.pcap (+ .txt: tshark summary). Leaves nothing running.
set -u
NAME=$1; ALGS=${2:-MD5}
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/$ALGS/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 &
OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp port 5060' 2>/dev/null & TCPD=$!; sleep 1
S=scenarios; P="-i 192.0.2.22 -p 5060 -m 1 -timeout 20s -timeout_error -nostdin -bg"
sipp 192.0.2.10:5060 -sf $S/reg.xml -s 2002 -auth_uri lab.sip -au 2002 -ap lab-2002-pass -i 192.0.2.22 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg 2002 failed"
sipp -sf $S/answer.xml -s 2002 -i 192.0.2.22 -p 5060 -mp 40000 -m 1 -timeout 30s -nostdin > /dev/null 2>&1 & UAS=$!
sleep 1
sipp 192.0.2.10:5060 -sf $S/reg.xml -s 2001 -auth_uri lab.sip -au 2001 -ap lab-2001-pass -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg 2001 failed"
sipp 192.0.2.10:5060 -sf $S/call.xml -s 2001 -set callee 2002 -auth_uri 2002@lab.sip -au 2001 -ap lab-2001-pass -i 192.0.2.21 -p 5060 -mp 30000 -m 1 -timeout 20s -timeout_error -nostdin > /dev/null 2>&1 || echo "call failed"
wait $UAS 2>/dev/null
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt
