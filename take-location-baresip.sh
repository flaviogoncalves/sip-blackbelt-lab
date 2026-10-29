#!/bin/bash
# sip-lab take for lesson 2.1 with baresip: 2001 and 2002 register, then read the location table while they are up.
#   sudo ./take-location-baresip.sh <name>
set -u
NAME=$1
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp port 5060' 2>/dev/null & TCPD=$!; sleep 1
D1=$(./baresip-conf.sh 2001 192.0.2.21 2001 2001 lab-2001-pass)
D2=$(./baresip-conf.sh 2002 192.0.2.22 2002 2002 lab-2002-pass)
timeout 12 baresip -f "$D1" -t 12 -s > captures/$NAME.2001.log 2>&1 & P1=$!
timeout 12 baresip -f "$D2" -t 12 -s > captures/$NAME.2002.log 2>&1 & P2=$!
sleep 4
opensips-cli -x mi usrloc:dump > captures/$NAME.location.txt 2>&1
wait $P1 $P2 2>/dev/null
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt; echo "=== location ==="; cat captures/$NAME.location.txt
