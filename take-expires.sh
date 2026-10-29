#!/bin/bash
# sip-lab take for lesson 2.3: Expires 120, Expires 30 -> 423, two contacts on one AOR, Expires 0.
#   sudo ./take-expires.sh <name>
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
sipp 192.0.2.10:5060 -sf $S/reg-expires.xml -s 2001 -set expires 120 -auth_uri lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "expires 120 failed"
sipp 192.0.2.10:5060 -sf $S/reg-expires-short.xml -s 2001 -set expires 30 -auth_uri lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "expires 30 failed"
sipp 192.0.2.10:5060 -sf $S/reg.xml -s 2001 -auth_uri lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg 3600 failed"
sipp 192.0.2.10:5060 -sf $S/reg.xml -s 2001 -auth_uri lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.23 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "second contact failed"
opensips-cli -x mi usrloc:dump > captures/$NAME.location.txt 2>&1
sipp 192.0.2.10:5060 -sf $S/reg-unregister.xml -s 2001 -auth_uri lab.sip -au 2001 -ap lab-2001-pass \
  -i 192.0.2.21 -p 5060 -m 1 -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "unregister failed"
opensips-cli -x mi usrloc:dump > captures/$NAME.location-after.txt 2>&1
sleep 1; kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; wait 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
cat captures/$NAME.txt; echo "=== location ==="; cat captures/$NAME.location.txt; echo "=== after unregister ==="; cat captures/$NAME.location-after.txt
