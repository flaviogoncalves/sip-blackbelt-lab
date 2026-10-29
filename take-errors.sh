#!/bin/bash
# sip-lab takes for section 4 part A (errors, extensions and overload). Same plumbing as take-media.sh and take-route.sh:
# baresip phones (baresip-phone.sh, driven by bctl.py), SIPp where a scripted request or reply is needed, sipsend.py for
# hand-written (broken) requests. Some cases run lab.cfg with one change, saved as captures/<name>.cfg.diff.
#   sudo ./take-errors.sh <case> <name>
# Cases: badreq ext420 body415 loop483 glare491 busy503 busy503srv timer422 rtptimeout ticket ticketfix
# Writes captures/<name>.pcap (SIP + RTP + ICMP on lo), .txt (SIP summary), .rtp.txt (RTP streams), .media.txt and the
# logs of every element. Leaves nothing running: tc, extra addresses, /etc/hosts lines and dnsmasq are removed.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x dnsmasq 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
mkdir -p /run/opensips
S=scenarios
B1=4401; B2=4402
ADDRS=()   # addresses this take added to lab0
HOSTS=()   # /etc/hosts lines this take added
rm -f captures/$NAME.*

# lab.cfg as the take needs it
CFG=/tmp/lab-take.cfg
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > $CFG
PLAIN=/tmp/lab-take-plain.cfg; cp $CFG $PLAIN
edit() {  # edit <old> <new>: replace the first <old> in the take's cfg (fails loudly if <old> is missing)
  python3 - "$CFG" "$1" "$2" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if old not in s:
    sys.exit(f"cfg edit: {old!r} not found")
open(p, "w").write(s.replace(old, new, 1))
EOF
}
addr() { ip addr add "$1/32" dev lab0 2>/dev/null; ADDRS+=("$1"); }
host() { grep -qx "$1" /etc/hosts || { echo "$1" >> /etc/hosts; HOSTS+=("$1"); }; }
LOOKUP=$'\tif (!lookup("location")) {\n'
case $CASE in
  # the second half of the take: every request checked before routing (400), and 405 + Allow for SUBSCRIBE
  badreq) edit $'route {\n' $'route {\n\t# lesson 4.1: check every request (headers, SDP) before routing it; a malformed one gets 400 Bad Request\n\tif (!sipmsg_validate("sh", $var(reason))) {\n\t\t$var(rc) = $retcode;\n\t\tif ($var(rc) == -21)\n\t\t\t$var(reason) = "no Content-Type header";   # the module gives no text for this one\n\t\txlog("sipmsg_validate() = $var(rc) ($var(reason)) for $rm from $si:$sp: 400\\n");\n\t\tappend_to_reply("Warning: 399 lab.sip \\"$var(reason)\\"\\r\\n");\n\t\tsend_reply(400, "Bad Request");\n\t\texit;\n\t}\n\t# lesson 4.1: this proxy has no presence service, so SUBSCRIBE is a method it knows but does not allow here\n\tif (is_method("SUBSCRIBE")) {\n\t\tappend_to_reply("Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, INFO, MESSAGE, UPDATE, PRACK, REFER, NOTIFY\\r\\n");\n\t\tsend_reply(405, "Method Not Allowed");\n\t\texit;\n\t}\n' ;;
  # calls for voip.example go out by DNS, and (the fault) voip.example resolves to this proxy: /etc/hosts line below
  loop483) edit "$LOOKUP" $'\t# calls for the voip.example domain go to its server, found by DNS\n\tif ($rd == "voip.example") {\n\t\tt_relay();\n\t\texit;\n\t}\n'"$LOOKUP"
           host "192.0.2.10 voip.example" ;;
  # proxy A (192.0.2.10) sends 0800 numbers to proxy B (192.0.2.11, a second socket of this OpenSIPS), which trusts A
  # by address; the ticket: B's route for 0800 points back at A. The fix: B sends 0800 to the gateway at 192.0.2.22.
  ticket|ticketfix)
           [ $CASE = ticket ] && DU="sip:192.0.2.10:5060" || DU="sip:192.0.2.22:5060"
           edit $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\nsocket=udp:192.0.2.11:5060\n'
           edit $'\tif (has_totag()) {\n' $'\t# proxy B (192.0.2.11): the toll-free side; it routes 0800 numbers on\n\tif ($socket_in(ip) == "192.0.2.11" && !has_totag() && !is_method("CANCEL")) {\n\t\trecord_route();\n\t\tif ($rU =~ "^0800") {\n\t\t\t$du = "'"$DU"$'";\n\t\t\tforce_send_socket(\"udp:192.0.2.11:5060\");\n\t\t\tt_relay();\n\t\t\texit;\n\t\t}\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\n\tif (has_totag()) {\n'
           edit $'\tif ($fd == "lab.sip") {\n' $'\tif ($fd == "lab.sip" && $si != "192.0.2.11") {\t# proxy B is trusted by its address\n'
           edit "$LOOKUP" $'\t# proxy A: toll-free numbers go to proxy B\n\tif ($rU =~ "^0800") {\n\t\t$du = "sip:192.0.2.11:5060";\n\t\tforce_send_socket(\"udp:192.0.2.10:5060\");\n\t\tt_relay();\n\t\texit;\n\t}\n'"$LOOKUP"
           addr 192.0.2.11 ;;
  # SRV failover: sip1 (192.0.2.11, a SIPp server answering 503) and sip2 (192.0.2.12, OpenSIPS); no digest in this take,
  # so every request is one transaction (as take-route.sh's dns case)
  busy503srv)
           edit $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\nsocket=udp:192.0.2.12:5060\n'
           python3 - "$CFG" <<'EOF'
import sys, re
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'\t\troute\(credentials\);\n\t\tif \(!pv_www_authorize.*?\t\tif \(\$au != \$tU\) \{.*?\t\t\}\n', '\t\t# no digest in this take\n', s, count=1, flags=re.S)
s = re.sub(r'\tif \(\$fd == "lab.sip"\) \{.*?consume_credentials\(\);\n\t\}\n', '\t# no proxy authentication in this take\n', s, count=1, flags=re.S)
open(p, "w").write(s)
EOF
           addr 192.0.2.11; addr 192.0.2.12 ;;
esac
cmp -s $PLAIN $CFG || diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

osips() {  # osips <cfg> <log>
  /usr/sbin/opensips -F -f "$1" > "$2" 2>&1 & OSIPS=$!; sleep 2
}
if [ $CASE = badreq ]; then osips $PLAIN captures/$NAME.opensips.log; else osips $CFG captures/$NAME.opensips.log; fi
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] ["key value" config line]
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" "${6:-}")
  if [ -n "${7:-}" ]; then  # replace the key's line, commented or not (baresip reads the first one), or add it
    local k=${7%% *} v=${7#* }
    if grep -q "^#\?$k[[:space:]]" "$d/config"; then sed -i "0,/^#\?$k[[:space:]].*/s||$k\t\t$v|" "$d/config"
    else printf '%s\t\t%s\n' "$k" "$v" >> "$d/config"; fi
  fi
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
uas() {  # uas <scenario> <seconds> <log tag> [ip [sipp options]]: a SIPp callee (default 2002 at 192.0.2.22, one call)
  local sc=$1 t=$2 tag=$3 ip=${4:-192.0.2.22}; shift 3; [ $# -gt 0 ] && shift
  [ $# -eq 0 ] && set -- -m 1
  timeout "$t" sipp -sf $S/$sc -s 2002 -i "$ip" -p 5060 -mp 40000 -timeout "${t}s" -nostdin "$@" \
    > captures/$NAME.$tag.log 2>&1 &
}
uac() {  # uac <scenario> <seconds> <log tag> <user> <ip> <rtp port> [sipp options]: a SIPp caller through the proxy
  local sc=$1 t=$2 tag=$3 u=$4 ip=$5 mp=$6; shift 6
  timeout "$t" sipp 192.0.2.10:5060 -sf $S/$sc -s "$u" -au "$u" -ap "lab-$u-pass" -i "$ip" -p 5060 -mp "$mp" -m 1 \
    -timeout "${t}s" -nostdin "$@" > captures/$NAME.$tag.log 2>&1 || echo "$tag: sipp ended with an error"
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
dial() { ctl 0 $B1 dial "${1:-sip:2002@lab.sip}"; }
send() { ./sipsend.py "$@" >> captures/$NAME.sipsend.txt 2>&1; }
note() { echo "### $*" >> captures/$NAME.sipsend.txt; }
R=requests
BROKEN="$R/no-call-id.sip $R/bad-content-length.sip $R/sdp-garbage.sip $R/sdp-no-content-type.sip"

case $CASE in
  # broken requests to the proxy: plain lab.cfg (it drops or forwards them), then lab.cfg with sipmsg_validate() (400)
  # and 405 + Allow for SUBSCRIBE; an unknown method straight to phone 2002 (501)
  badreq)   phone 2002 192.0.2.22 $B2 40000 60; sleep 3
            note "lab.cfg as it is (sent from 192.0.2.21 to the proxy 192.0.2.10)"; send 192.0.2.10 $BROKEN
            kill $OSIPS; sleep 1; osips $CFG captures/$NAME.opensips-validate.log
            note "lab.cfg with sipmsg_validate() and 405 for SUBSCRIBE (captures/$NAME.cfg.diff)"
            send 192.0.2.10 $BROKEN $R/subscribe.sip
            note "an unknown method straight to phone 2002 (192.0.2.22)"; send 192.0.2.22 $R/foo.sip ;;
  # 2002 (SIPp) calls baresip 2001 with Require: 100rel -> 420 + Unsupported; then baresip 2001 calls a 2002 that
  # requires 100rel (SIPp) -> 421 + Require
  ext420)   phone 2001 192.0.2.21 $B1 30000 22 ";answermode=auto"; sleep 3
            uac call-require.xml 8 uac 2002 192.0.2.22 40000 -set callee 2001 -auth_uri 2001@lab.sip; sleep 1
            sipp_reg 2002 192.0.2.22; uas uas-421.xml 10 uas; sleep 1; dial; sleep 5 ;;
  # 2001 (SIPp) sends phone 2002 a MESSAGE of a type it does not read (415 + Accept), then the same text as text/plain
  body415)  phone 2002 192.0.2.22 $B2 40000 20; sleep 3
            uac message.xml 8 uac 2001 192.0.2.21 30000 -set callee 2002 -set ctype application/x-nonsense \
              -set body "Meeting moved to 3 pm" -auth_uri 2002@lab.sip; sleep 1
            uac message.xml 8 uac2 2001 192.0.2.21 30000 -set callee 2002 -set ctype text/plain \
              -set body "Meeting moved to 3 pm" -auth_uri 2002@lab.sip ;;
  # an INVITE from another domain to sip:2002@voip.example: the proxy relays it to itself until Max-Forwards is 0
  loop483)  uac call-loop.xml 15 uac 2001 192.0.2.21 30000 -set ruri sip:2002@voip.example; sleep 1 ;;
  # two phones in a call put each other on hold at the same moment: the re-INVITEs cross (491) and are retried.
  # On one box a re-INVITE is answered in a few ms, so SIP gets 50 ms of delay per hop (tc netem on packets from port
  # 5060, from the hold on), as between distant sites: the two holds, sent ~20 ms apart, then cross in flight.
  glare491) phone 2002 192.0.2.22 $B2 40000 30 ";answermode=auto"; phone 2001 192.0.2.21 $B1 30000 30
            sleep 3; dial; sleep 4
            tc qdisc add dev lo root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
            tc qdisc add dev lo parent 1:4 handle 40: netem delay 50ms
            tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport 5060 0xffff flowid 1:4
            tc -s qdisc show dev lo > captures/$NAME.netem.txt
            ctl 0 $B1 hold & H1=$!; ctl 0 $B2 hold & H2=$!; wait $H1 $H2
            sleep 10; ctl 0 $B1 hangup; sleep 2
            tc -s qdisc show dev lo >> captures/$NAME.netem.txt; tc qdisc del dev lo root ;;
  # 2002 (SIPp) is overloaded: 503 + Retry-After: 120 to baresip 2001's call through the proxy
  busy503)  sipp_reg 2002 192.0.2.22; uas uas-503.xml 14 uas; phone 2001 192.0.2.21 $B1 30000 12; sleep 3; dial; sleep 7 ;;
  # lab.sip SRV: sip1 (priority 10) answers 503 + Retry-After to everything, sip2 (priority 20) is OpenSIPS. Does the
  # phone (it resolves lab.sip through dnsmasq) move to sip2 for its REGISTER and its INVITE?
  busy503srv)
            dnsmasq --keep-in-foreground --port=5353 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --no-hosts \
              --log-queries --log-facility=- --local=/lab.sip/ \
              --naptr-record=lab.sip,10,50,S,SIP+D2U,,_sip._udp.lab.sip \
              --srv-host=_sip._udp.lab.sip,sip1.lab.sip,5060,10,50 --srv-host=_sip._udp.lab.sip,sip2.lab.sip,5060,20,50 \
              --host-record=sip1.lab.sip,192.0.2.11 --host-record=sip2.lab.sip,192.0.2.12 \
              > captures/$NAME.dns.log 2>&1 & DNSM=$!; sleep 1
            for q in "NAPTR lab.sip" "SRV _sip._udp.lab.sip" "A sip1.lab.sip" "A sip2.lab.sip"; do
              echo "\$ dig +noall +answer @127.0.0.1 -p 5353 $q"; dig +noall +answer @127.0.0.1 -p 5353 $q
            done > captures/$NAME.dig.txt
            uas uas-503-any.xml 40 sip1 192.0.2.11 -m 10   # every request is a new SIPp call
            phone 2002 192.0.2.22 $B2 40000 36 ';answermode=auto;answerdelay=2000;outbound="sip:192.0.2.10"'
            phone 2001 192.0.2.21 $B1 30000 36 ";regint=600" "dns_server 127.0.0.1:5353"
            sleep 8; dial; ctl 14 $B1 hangup; sleep 6
            kill $DNSM 2>/dev/null ;;
  # session timers between SIPp phones through the proxy: 422 + Min-SE, retry, refresh at 45 s, BYE; then a call that is
  # never refreshed: the callee sends BYE 60 s after the 200
  timer422) sipp_reg 2002 192.0.2.22; sipp_reg 2001 192.0.2.21
            uas uas-timer.xml 70 uas; sleep 1
            uac call-timer.xml 65 uac 2001 192.0.2.21 30000 -set callee 2002 -auth_uri 2002@lab.sip; sleep 2
            uas uas-timer-expire.xml 80 uas2; sleep 1
            uac call-timer-norefresh.xml 75 uac2 2001 192.0.2.21 30000 -set callee 2002 -auth_uri 2002@lab.sip ;;
  # an in-dialog OPTIONS (SIPp 2003 calls baresip 2002) answered 200; then baresip 2001 (rtp_timeout 10) calls 2002,
  # 2002's media is cut (netem loss 100% on its ports 40000-40015) and 2001 hangs up on its own
  rtptimeout)
            phone 2002 192.0.2.22 $B2 40000 50 ";answermode=auto;answerdelay=1000"; sleep 3
            uac call-options.xml 12 uac 2003 192.0.2.23 50000 -set callee 2002 -auth_uri 2002@lab.sip; sleep 1
            phone 2001 192.0.2.21 $B1 30000 40 "" "rtp_timeout 10"; sleep 3; dial; sleep 6
            tc qdisc add dev lo root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
            tc qdisc add dev lo parent 1:4 handle 40: netem loss 100%
            tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport 40000 0xfff0 flowid 1:4
            date +"%T.%N media of 2002 cut" > captures/$NAME.netem.txt; tc -s qdisc show dev lo >> captures/$NAME.netem.txt
            sleep 16; tc -s qdisc show dev lo >> captures/$NAME.netem.txt; tc qdisc del dev lo root ;;
  # the 483 ticket: a call to 0800 5550100 goes A -> B -> A -> B ... until Max-Forwards runs out
  ticket)   sipp_reg 2001 192.0.2.21
            uac call-ticket.xml 15 uac 2001 192.0.2.21 30000 -set callee 08005550100 -auth_uri 08005550100@lab.sip; sleep 1 ;;
  # the fix: B sends 0800 to the gateway (SIPp at 192.0.2.22) and the call is answered
  ticketfix) uas answer.xml 14 uas; sipp_reg 2001 192.0.2.21; sleep 1
            uac call.xml 12 uac 2001 192.0.2.21 30000 -set callee 08005550100 -auth_uri 08005550100@lab.sip; sleep 1 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x dnsmasq 2>/dev/null
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
for h in "${HOSTS[@]}"; do sed -i "/^${h//./\\.}\$/d" /etc/hosts; done
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -Y "rtp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
cat captures/$NAME.txt; [ -s captures/$NAME.sipsend.txt ] && { echo "=== sipsend ==="; cat captures/$NAME.sipsend.txt; }
echo "=== rtp ==="; cat captures/$NAME.rtp.txt
