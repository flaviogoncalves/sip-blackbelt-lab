#!/bin/bash
# sip-lab takes for chapter 4 (transactions, dialogs and routing). Same plumbing as take-call.sh; some cases run
# OpenSIPS with one change to lab.cfg (no record_route, a 302 redirect, a B2BUA, a 32 s transaction timer, a second
# address for DNS) and some drop packets with iptables to play a dead or firewalled host (DROP, so no ICMP either).
#   sudo ./take-route.sh <case> <name>
# Cases: trans timera timerb timerf bye481 via rr norr redirect b2b dns fork ticket ticketfix
# Writes captures/<name>.pcap (SIP + RTP + ICMP on lo), .txt (SIP summary), .rtp.txt, .media.txt. Leaves nothing running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x dnsmasq 2>/dev/null; sleep 1
mkdir -p /run/opensips
S=scenarios
B1=4401; B2=4402; B3=4403
DROPS=()   # iptables INPUT rules this take added (removed at the end)

# lab.cfg as the take needs it (the change is printed into the take's log)
CFG=/tmp/lab-take.cfg
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > $CFG
before_rr() {  # insert script lines just before record_route()
  python3 - "$CFG" "$1" <<'EOF'
import sys
p, block = sys.argv[1], sys.argv[2]
s = open(p).read()
s = s.replace("\trecord_route();\n", block + "\trecord_route();\n", 1)
open(p, "w").write(s)
EOF
}
case $CASE in
  timerb) sed -i 's/modparam("tm", "fr_timeout", 5)/modparam("tm", "fr_timeout", 32)/' $CFG ;;
  norr|ticket) sed -i 's/^\trecord_route();/\t# record_route(); left out in this take/' $CFG ;;
  redirect) before_rr $'\t# a redirect server: answer 302 with the registered Contact instead of relaying\n\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\tappend_to_reply("Contact: <$ru>\\r\\n");\n\tsend_reply(302, "Moved Temporarily");\n\texit;\n' ;;
  b2b) sed -i 's/^loadmodule "rr.so"/loadmodule "b2b_entities.so"\nloadmodule "b2b_logic.so"\n&/' $CFG
       before_rr $'\t# a B2BUA: end this call here and place a new one to the registered Contact\n\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\tb2b_init_request("top hiding");\n\texit;\n' ;;
  dns) sed -i 's/^socket=udp:192.0.2.10:5060/&\nsocket=udp:192.0.2.12:5060/' $CFG   # sip2.lab.sip; sip1 = .11 is dead
       # no digest in this take: every request is one transaction, so each failover shows once
       python3 - "$CFG" <<'EOF2'
import sys, re
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'\t\troute\(credentials\);\n\t\tif \(!pv_www_authorize.*?\t\tif \(\$au != \$tU\) \{.*?\t\t\}\n', '\t\t# no digest in this take\n', s, count=1, flags=re.S)
s = re.sub(r'\tif \(\$fd == "lab.sip"\) \{.*?consume_credentials\(\);\n\t\}\n', '\t# no proxy authentication in this take\n', s, count=1, flags=re.S)
open(p, "w").write(s)
EOF2
       ip addr add 192.0.2.11/32 dev lab0 2>/dev/null; ip addr add 192.0.2.12/32 dev lab0 2>/dev/null ;;
esac
diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff

drop() {  # drop <iptables match...>: the host is there but never answers
  iptables -I INPUT "$@" -j DROP; DROPS+=("$*")
}

/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] [config name]
  local d n=${7:-$1}; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" "${6:-}" "$n")
  [ "$CASE" = dns ] && [ "$n" = 2001 ] && printf 'dns_server 127.0.0.1:5353\n' >> "$d/config"   # only 2001 resolves lab.sip
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$n.log 2>&1 &
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
both() {  # both <seconds> [callee params]: baresip 2002 (auto answer after 2 s) and baresip 2001
  phone 2002 192.0.2.22 $B2 40000 "$1" "${2:-;answermode=auto;answerdelay=2000}"; phone 2001 192.0.2.21 $B1 30000 "$1"
}

case $CASE in
  # one call, the callee hangs up: INVITE/407/ACK, INVITE/1xx/200, ACK, BYE from the other side
  trans)    both 14; sleep 3; dial; ctl 7 $B2 hangup; sleep 4 ;;
  # INVITE to a registered phone that never answers: the proxy's client transaction runs Timer A to Timer B
  timerb)   sipp_reg 2002 192.0.2.22; drop -d 192.0.2.22 -p udp --dport 5060; phone 2001 192.0.2.21 $B1 30000 42
            sleep 3; dial; sleep 37 ;;
  # INVITE from a phone straight to an address that never answers: the phone's own Timer A doubling, Timer B at 32 s
  timera)   drop -d 192.0.2.22 -p udp --dport 5060; phone 2001 192.0.2.21 $B1 30000 42
            sleep 3; ctl 0 $B1 dial sip:2002@192.0.2.22; sleep 37 ;;
  # OPTIONS from a phone straight to an address that never answers: Timer E up to T2, Timer F at 32 s
  timerf)   drop -d 192.0.2.22 -p udp --dport 5060; phone 2001 192.0.2.21 $B1 30000 42
            sleep 3; ctl 0 $B1 options sip:2002@192.0.2.22; sleep 37 ;;
  # a BYE with a To-tag of no dialog (481), then the right one (200)
  bye481)   phone 2002 192.0.2.22 $B2 40000 20 ";answermode=auto;answerdelay=1000"; sleep 2; sipp_uac call-bye481.xml 16 ;;
  # a caller whose Via says 192.168.1.21: the proxy adds received and rport
  via)      phone 2002 192.0.2.22 $B2 40000 16 ";answermode=auto;answerdelay=1000"; sleep 2; sipp_uac call-via.xml 12 ;;
  # the same call with and without record_route(): where do the ACK and the BYE go
  rr|norr)  both 14; sleep 3; dial; ctl 7 $B1 hangup; sleep 4 ;;
  # 302 from the proxy, the caller re-INVITEs the Contact itself
  redirect) phone 2002 192.0.2.22 $B2 40000 18 ";answermode=auto;answerdelay=1000"; sleep 2; sipp_uac call-redirect.xml 14 ;;
  # the proxy as a B2BUA: two Call-IDs
  b2b)      both 14; sleep 3; dial; ctl 7 $B1 hangup; sleep 4 ;;
  # lab.sip NAPTR -> SRV sip1 (priority 10, dead) and sip2 (priority 20, OpenSIPS); the phone registers and calls
  dns)      dnsmasq --keep-in-foreground --port=5353 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --no-hosts \
              --log-queries --log-facility=- --local=/lab.sip/ \
              --naptr-record=lab.sip,10,50,S,SIP+D2U,,_sip._udp.lab.sip \
              --srv-host=_sip._udp.lab.sip,sip1.lab.sip,5060,10,50 --srv-host=_sip._udp.lab.sip,sip2.lab.sip,5060,20,50 \
              --host-record=sip1.lab.sip,192.0.2.11 --host-record=sip2.lab.sip,192.0.2.12 \
              > captures/$NAME.dns.log 2>&1 & DNSM=$!; sleep 1
            for q in "NAPTR lab.sip" "SRV _sip._udp.lab.sip" "A sip1.lab.sip" "A sip2.lab.sip"; do
              echo "\$ dig +noall +answer @127.0.0.1 -p 5353 $q"; dig +noall +answer @127.0.0.1 -p 5353 $q
            done > captures/$NAME.dig.txt
            drop -d 192.0.2.11 -p udp --dport 5060
            phone 2002 192.0.2.22 $B2 40000 92 ';answermode=auto;answerdelay=2000;outbound="sip:192.0.2.10"'
            phone 2001 192.0.2.21 $B1 30000 92 ";regint=600"
            sleep 38; dial; ctl 40 $B1 hangup; sleep 4
            kill $DNSM 2>/dev/null ;;
  # two phones registered as 2002 (.22 answers after 3 s, .23 keeps ringing): parallel fork, CANCEL to the loser
  fork)     phone 2002 192.0.2.22 $B2 40000 16 ";answermode=auto;answerdelay=3000"; phone 2002 192.0.2.23 $B3 50000 16 "" 2002b
            phone 2001 192.0.2.21 $B1 30000 16; sleep 3; dial; ctl 8 $B1 hangup; sleep 4 ;;
  # no record_route() and 2001 accepts SIP only from the proxy: 2002 hangs up, its BYE goes straight to 2001 and is lost
  ticket)   drop -s 192.0.2.22 -d 192.0.2.21 -p udp --dport 5060
            both 48; sleep 3; dial; ctl 6 $B2 hangup; sleep 38 ;;
  # the fix: the same firewall, record_route() back in: the BYE goes through the proxy and 2001 answers 200
  ticketfix) drop -s 192.0.2.22 -d 192.0.2.21 -p udp --dport 5060
            both 16; sleep 3; dial; ctl 6 $B2 hangup; sleep 6 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
for r in "${DROPS[@]}"; do iptables -D INPUT $r -j DROP; done
[ "$CASE" = dns ] && { ip addr del 192.0.2.11/32 dev lab0; ip addr del 192.0.2.12/32 dev lab0; } 2>/dev/null
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -Y "rtp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
cat captures/$NAME.txt; echo "=== rtp ==="; cat captures/$NAME.rtp.txt
