#!/bin/bash
# sip-lab call takes for chapter 3 (INVITE to BYE). baresip phones where a real phone can do it, SIPp where the case
# needs a scripted reply (486, 480, 421, early media, a reliable 183, a Reason header, a private Contact; baresip 1.1
# crashes on its own answermode=early).
#   sudo ./take-call.sh <case> <name>
# Cases: basic cancel busy noanswer timeout early hold codec reason prack prack421 private
# Writes captures/<name>.pcap (SIP + RTP + ICMP on lo), .txt (SIP summary), .rtp.txt (RTP streams). Leaves nothing running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
mkdir -p /run/opensips
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1
S=scenarios
B1=4401; B2=4402

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params]
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" "${6:-}")
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
sipp_uas() {  # sipp_uas <scenario> <seconds>
  timeout "$2" sipp -sf $S/$1 -s 2002 -i 192.0.2.22 -p 5060 -mp 40000 -m 1 -max_retrans 100 -max_invite_retrans 100 -timeout "${2}s" -nostdin \
    > captures/$NAME.uas.log 2>&1 &
}
sipp_uac() {  # sipp_uac <scenario> <seconds>
  sipp_reg 2001 192.0.2.21
  timeout "$2" sipp 192.0.2.10:5060 -sf $S/$1 -s 2001 -set callee 2002 -auth_uri 2002@lab.sip -au 2001 -ap lab-2001-pass \
    -i 192.0.2.21 -p 5060 -mp 30000 -m 1 -timeout "${2}s" -nostdin > captures/$NAME.uac.log 2>&1 || echo "call failed"
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
dial() { ctl 0 $B1 dial sip:2002@lab.sip; }

case $CASE in
  basic)    phone 2002 192.0.2.22 $B2 40000 14 ";answermode=auto;answerdelay=2000"; phone 2001 192.0.2.21 $B1 30000 14
            sleep 3; dial; ctl 7 $B1 hangup; sleep 4 ;;
  cancel)   phone 2002 192.0.2.22 $B2 40000 12; phone 2001 192.0.2.21 $B1 30000 12
            sleep 3; dial; ctl 4 $B1 hangup; sleep 5 ;;
  busy)     sipp_reg 2002 192.0.2.22; sipp_uas uas-busy.xml 15; phone 2001 192.0.2.21 $B1 30000 12
            sleep 3; dial; sleep 8 ;;
  noanswer) sipp_reg 2002 192.0.2.22; sipp_uas uas-noanswer.xml 20; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial; sleep 12 ;;
  timeout)  sipp_reg 2002 192.0.2.22; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial; sleep 12 ;;
  early)    sipp_reg 2002 192.0.2.22; sipp_uas uas-early.xml 20; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial; ctl 9 $B1 hangup; sleep 3 ;;
  hold)     phone 2002 192.0.2.22 $B2 40000 18 ";answermode=auto"; phone 2001 192.0.2.21 $B1 30000 18
            sleep 3; dial; ctl 3 $B1 hold; ctl 4 $B1 resume; ctl 3 $B1 hangup; sleep 3 ;;
  codec)    phone 2002 192.0.2.22 $B2 40000 16 ";answermode=auto"; sleep 2; sipp_uac reinvite-codec.xml 14 ;;
  reason)   sipp_reg 2002 192.0.2.22; sipp_uas answer.xml 20; sleep 1; sipp_uac call-reason.xml 15 ;;
  prack)    sipp_reg 2002 192.0.2.22; sipp_uas uas-100rel.xml 20; sleep 1; sipp_uac call-100rel.xml 15 ;;
  prack421) sipp_reg 2002 192.0.2.22; sipp_uas uas-421.xml 12; phone 2001 192.0.2.21 $B1 30000 10
            sleep 3; dial; sleep 5 ;;
  private)  ip addr add 192.168.1.22/32 dev lab0 2>/dev/null
            sipp_reg 2002 192.0.2.22; sipp_uas uas-private.xml 50; phone 2001 192.0.2.21 $B1 30000 46
            sleep 3; dial; sleep 42
            ip addr del 192.168.1.22/32 dev lab0 2>/dev/null ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -Y "rtp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt 2>/dev/null
done
cat captures/$NAME.txt; echo "=== rtp ==="; cat captures/$NAME.rtp.txt
