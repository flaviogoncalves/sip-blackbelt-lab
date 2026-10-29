#!/bin/bash
# sip-lab takes for section 4 part B (NAT traversal). A real NAT built with network namespaces (nat.sh): phone 2001 at
# 192.168.1.21 in a "home" behind a "router" that masquerades to 198.51.100.21; OpenSIPS 192.0.2.10 and phone 2002
# 192.0.2.22 on the internet side (the root namespace). Same plumbing as take-media.sh and take-errors.sh; some cases run
# lab.cfg with OpenSIPS nathelper and/or rtpengine added, saved as captures/<name>.cfg.diff.
#   sudo ./take-nat.sh <case> <name>
# Cases: nat behave expire keepalive nathelper alg alg-off relay stun ticket ticketfix
# Writes captures/<name>.pcap (the internet side: what OpenSIPS and 2002 see, plus what goes into the void toward
# 192.168.0.0/16), captures/<name>.home.pcap (the home side of the router: what 2001 sends and gets), .txt / .rtp.txt /
# .media.txt for both, .conntrack.txt (the router's NAT table at moments of the take), and the logs of every element.
# Leaves nothing running: the namespaces, rtpengine, coturn, the SIP ALG modules and the added addresses are removed.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
for p in opensips baresip sipp dnsmasq rtpengine turnserver; do pkill -x $p 2>/dev/null; done; sleep 1
mkdir -p /run/opensips
./nat.sh down; ./nat.sh up random > /dev/null    # a fresh NAT (empty table) for every take; random external ports
RTR="ip netns exec router"; HM="ip netns exec home"
B1=4401; B2=4402
ADDRS=()   # addresses this take added to lab0
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
nathelper() {  # nathelper <natping interval, 0 = none>: OpenSIPS fixes the signaling of a phone behind a NAT
  edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# lesson 4.12: NAT traversal on the server\nloadmodule "nathelper.so"\nmodparam("nathelper", "received_avp", "$avp(received)")\t# fix_nated_register() puts the source address here\nmodparam("registrar", "received_avp", "$avp(received)")\t# and the registrar keeps it with the binding\nmodparam("usrloc", "nat_bflag", "NAT")\t\t\t# a binding registered from behind a NAT\nmodparam("nathelper", "natping_interval", '"$1"$')\t\t# seconds between keepalives (0 = none)\nmodparam("nathelper", "ping_nated_only", 1)\nmodparam("nathelper", "sipping_bflag", "SIPPING")\t# keepalive = an OPTIONS request, not an empty packet\nmodparam("nathelper", "sipping_from", "sip:keepalive@lab.sip")\n'
  edit $'\tif (has_totag()) {\n' $'\t# lesson 4.12: answer to the address and port the request came from (rport), and when the phone is behind a\n\t# NAT (private Contact, or a source that is not its Via) use that source instead of what the phone wrote\n\tforce_rport();\n\tif (nat_uac_test("private-contact,diff-ip-src-via,diff-port-src-via")) {\n\t\tif (is_method("REGISTER")) {\n\t\t\tfix_nated_register();\t# the binding keeps ;received=<source address and port>\n\t\t\tsetbflag("NAT");\n\t\t\tsetbflag("SIPPING");\n\t\t} else {\n\t\t\tfix_nated_contact();\t# Contact: the source address and port\n\t\t}\n\t}\n\tt_on_reply("nat");\n\n\tif (has_totag()) {\n'
  printf '\n# lesson 4.12: a reply from a phone behind a NAT (the 200 OK of a callee at home)\nonreply_route[nat] {\n\tif (nat_uac_test("private-contact"))\n\t\tfix_nated_contact();\n#RELAY-ANSWER\n}\n' >> $CFG
}
relay() {  # rtpengine anchors the media of every call (lesson 4.14)
  edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# lesson 4.14: media relay\nloadmodule "rtpengine.so"\nmodparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")\n'
  edit $'\t\tif (loose_route()) {\n' $'\t\tif (is_method("BYE"))\n\t\t\trtpengine_delete();\t# the call is over: free the relay ports\n\t\tif (loose_route()) {\n'
  edit $'\tt_relay();\n}\n\n# the lab' $'\t# lesson 4.14: the media goes through rtpengine (the SDP gets its address and ports)\n\tif (is_method("INVITE") && has_body("application/sdp")) {\n\t\trtpengine_offer("replace-origin");\n\t\tsetflag("RELAY");\n\t}\n\tt_relay();\n}\n\n# the lab'
  edit $'#RELAY-ANSWER\n' $'\tif (isflagset("RELAY") && has_body("application/sdp"))\n\t\trtpengine_answer("replace-origin");\n'
}
case $CASE in
  expire)    nathelper 0 ;;
  keepalive) nathelper 10 ;;
  nathelper|ticket) nathelper 0 ;;
  relay|ticketfix)  nathelper 0; relay ;;
esac
sed -i '/^#RELAY-ANSWER$/d' $CFG
cmp -s $PLAIN $CFG || diff $PLAIN $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

RTPE=(rtpengine --config-file=none --interface=192.0.2.10 --listen-ng=127.0.0.1:2223 --listen-cli=127.0.0.1:9900
      --port-min=35000 --port-max=35099 --table=-1 --foreground --log-stderr --log-level=6 --pidfile=/tmp/rtpengine.pid)
case $CASE in relay|ticketfix)
  # rtpengine's own socket is bound to 192.0.2.10: like SIPp's, leave it untracked (net.sh explains why)
  iptables -t raw -I OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK
  echo "${RTPE[*]}" > captures/$NAME.rtpengine-cmdline.txt
  "${RTPE[@]}" > captures/$NAME.rtpengine.log 2>&1 & sleep 1 ;;   # before OpenSIPS: it pings rtpengine at start
esac
/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
# the home phone's DNS (its router's resolver, here inside the home namespace): lab.sip -> 192.0.2.10
$HM dnsmasq --keep-in-foreground --port=5353 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --no-hosts \
  --local=/lab.sip/ --host-record=lab.sip,192.0.2.10 > /dev/null 2>&1 &
# internet side: lo (OpenSIPS, 2002), natwan (to and from the router) and labvoid (sent to private addresses: lost)
tcpdump -i any -U -s 0 -w captures/$NAME.pcap \
  '(udp or icmp) and (net 192.0.2.0/24 or net 198.51.100.0/24 or net 192.168.0.0/16)' 2>/dev/null & TCPD=$!
$RTR tcpdump -i lan -U -s 0 -w captures/$NAME.home.pcap 'udp or icmp' 2>/dev/null & TCPH=$!
sleep 1

conf() {  # conf <dir> "key value": replace the key's line, commented or not (baresip reads the first one), or add it
  local k=${2%% *} v=${2#* }
  if grep -q "^#\?$k[[:space:]]" "$1/config"; then sed -i "0,/^#\?$k[[:space:]].*/s||$k\t\t$v|" "$1/config"
  else printf '%s\t\t%s\n' "$k" "$v" >> "$1/config"; fi
}
hphone() {  # hphone <seconds> [account params] ["key value" config line]: baresip 2001 at 192.168.1.21 behind the NAT
  local d; d=$(./baresip-phone.sh 2001 192.168.1.21 $B1 30000 ";audio_codecs=PCMU/8000/1${2:-}")
  conf "$d" "rtp_stats yes"; conf "$d" "dns_server 127.0.0.1:5353"; [ -n "${3:-}" ] && conf "$d" "$3"
  $HM timeout "$1" baresip -f "$d" -t "$1" -s > captures/$NAME.2001.log 2>&1 &
}
iphone() {  # iphone <seconds> [account params] ["key value" config line]: baresip 2002 at 192.0.2.22 on the internet side
  local d; d=$(./baresip-phone.sh 2002 192.0.2.22 $B2 40000 ";audio_codecs=PCMU/8000/1${2:-}")
  conf "$d" "rtp_stats yes"; [ -n "${3:-}" ] && conf "$d" "$3"
  timeout "$1" baresip -f "$d" -t "$1" -s > captures/$NAME.2002.log 2>&1 &
}
hctl() { sleep "$1"; $HM ./bctl.py $B1 "$2" "${3:-}" >> captures/$NAME.ctl.log 2>&1; }
ictl() { sleep "$1"; ./bctl.py $B2 "$2" "${3:-}" >> captures/$NAME.ctl.log 2>&1; }
ctrack() {  # ctrack <label>: the router's NAT table now
  { echo "### t=$(( $(date +%s) - T0 )) s: $1"; $RTR conntrack -L -p udp 2>&1
    [ $CASE = alg ] && { echo "# expectations (the ALG's holes for what the SIP said will come)"; $RTR conntrack -L expect 2>&1; }
    echo; } >> captures/$NAME.conntrack.txt
}
mapped() {  # the external port the NAT gave 192.168.1.21:5060 -> 192.0.2.10:5060 (last dport= of the entry)
  $RTR conntrack -L -p udp --orig-src 192.168.1.21 --orig-port-src 5060 --orig-dst 192.0.2.10 2>/dev/null |
    sed -n 's/.*dport=\([0-9]*\).*/\1/p' | head -1
}
probe() {  # probe <src ip> <src port> <dst port> <label>: one OPTIONS to the phone's public binding
  echo "### $4: OPTIONS from $1:$2 to 198.51.100.21:$3" >> captures/$NAME.filtering.txt
  python3 - "$1" "$2" "$3" >> captures/$NAME.filtering.txt 2>&1 <<'EOF'
import secrets, socket, sys
src, sport, dport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
t = secrets.token_hex(4)
msg = (f"OPTIONS sip:2001@198.51.100.21:{dport} SIP/2.0\r\nVia: SIP/2.0/UDP {src}:{sport};branch=z9hG4bK{t}\r\n"
       f"Max-Forwards: 70\r\nFrom: <sip:probe@{src}>;tag={t}\r\nTo: <sip:2001@lab.sip>\r\nCall-ID: {t}@{src}\r\n"
       "CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n").encode()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((src, sport)); s.settimeout(2)
    s.sendto(msg, ("198.51.100.21", dport))
    try:
        print("reply:", s.recv(65535).split(b"\r\n")[0].decode())
    except socket.timeout:
        print("no reply in 2 s (the NAT dropped it)")
EOF
}
sessions() {  # the call as rtpengine holds it: its ports toward each phone and the packets relayed
  local c; for c in $(rtpengine-ctl -ip 127.0.0.1 -port 9900 list sessions all | awk '/^ID:/ {print $2}'); do
    echo "\$ rtpengine-ctl list sessions $c"; rtpengine-ctl -ip 127.0.0.1 -port 9900 list sessions "$c"
  done > captures/$NAME.rtpengine-sessions.txt 2>&1
}
addr() { ip addr add "$1/32" dev lab0 2>/dev/null; ADDRS+=("$1"); }
turn() {  # coturn on 192.0.2.30 and .31 (two addresses: RFC 5780 NAT behaviour discovery), STUN + TURN (user 2001)
  addr 192.0.2.30; addr 192.0.2.31
  # its relay socket is bound to 192.0.2.30: like rtpengine's, leave it untracked (net.sh explains why)
  iptables -t raw -I OUTPUT -p udp -s 192.0.2.30 --sport 49160:49199 -j NOTRACK
  turnserver -n --listening-ip=192.0.2.30 --listening-ip=192.0.2.31 --listening-port=3478 --alt-listening-port=3479 \
    --relay-ip=192.0.2.30 --min-port=49160 --max-port=49199 --realm=lab.sip --lt-cred-mech --user=2001:lab-turn-pass \
    --no-tls --no-dtls --no-tcp-relay --no-cli --log-file=stdout --simple-log --pidfile=/tmp/turnserver.pid \
    > captures/$NAME.turnserver.log 2>&1 &
  sleep 2
}
T0=$(date +%s)

case $CASE in
  # 4.10: 2001 at home calls 2002 (one-way audio: 2002 sends to 192.168.1.21); 2002 hangs up (its BYE goes to
  # 192.168.1.21: lost); then 2002 calls 2001 (the INVITE goes to the registered 192.168.1.21: lost, 408)
  nat|alg|alg-off)
            if [ $CASE = alg ]; then   # the router's SIP ALG: the kernel's SIP conntrack helper with SIP NAT
              modprobe nf_nat_sip
              $RTR iptables -t raw -A PREROUTING -p udp --dport 5060 -j CT --helper sip
              { echo "\$ lsmod | grep sip"; lsmod | grep sip; echo "\$ iptables -t raw -S (router)"; $RTR iptables -t raw -S
                echo "\$ ls /sys/module/nf_conntrack_sip/parameters"; for f in /sys/module/nf_conntrack_sip/parameters/*; do
                echo "${f##*/} = $(cat $f)"; done; } > captures/$NAME.alg.txt
            fi
            iphone 50 ";answermode=auto;answerdelay=1000"; hphone 50 ";answermode=auto;answerdelay=1000"; sleep 3
            ctrack "2001 registered"
            hctl 0 dial sip:2002@lab.sip; sleep 6; ctrack "call 2001 -> 2002 up"
            ictl 6 hangup; sleep 8
            ictl 0 dial sip:2001@lab.sip; sleep 9; ctrack "after the call 2002 -> 2001"
            hctl 0 hangup; sleep 3 ;;
  # 4.11: the NAT table of a registration and a call; filtering (who may send to the phone's public binding);
  # RFC 5780 behaviour discovery (coturn) with random external ports and with port preservation; the UDP timeouts
  behave)   for f in nf_conntrack_udp_timeout nf_conntrack_udp_timeout_stream; do
              echo "$f = $($RTR cat /proc/sys/net/netfilter/$f)"; done > captures/$NAME.timeouts.txt
            iphone 30 ";answermode=auto;answerdelay=1000"; hphone 30; sleep 3; ctrack "2001 registered"
            hctl 0 dial sip:2002@lab.sip; sleep 5; ctrack "call 2001 -> 2002 up"; hctl 0 hangup; sleep 2
            ctrack "call over"
            P=$(mapped); echo "the phone's SIP binding: 192.168.1.21:5060 -> 198.51.100.21:$P" > captures/$NAME.filtering.txt
            kill $OSIPS; sleep 1   # the probes use OpenSIPS's own address and port
            probe 192.0.2.10 5060 "$P" "from the server the phone registered with (the binding's own peer)"
            probe 192.0.2.10 5070 "$P" "from the same server address, another port"
            probe 192.0.2.23 5060 "$P" "from another address"
            { echo "### router INPUT counters"; $RTR iptables -L INPUT -v -n; } >> captures/$NAME.filtering.txt
            pkill -x baresip; sleep 1   # (its un-REGISTER goes out now, not in the middle of the discovery)
            turn
            for m in random preserve; do
              ./nat.sh up $m > /dev/null; $RTR conntrack -F 2>/dev/null
              { echo "### NAT: MASQUERADE $([ $m = random ] && echo --random || echo '(ports preserved)')"
                $HM turnutils_natdiscovery -m -f 192.0.2.30 2>&1; echo; } >> captures/$NAME.natdiscovery.txt
            done ;;
  # 4.11/4.12: nathelper without keepalives: 2001 registers (its binding: received=198.51.100.21:<port>), sends nothing
  # more; the router forgets the mapping after its UDP timeout, and a call to 2001 at ~40 s is lost (408)
  # keepalive: the same with OPTIONS pings every 10 s: the mapping stays and the call at ~40 s rings and is answered
  expire|keepalive)
            for f in nf_conntrack_udp_timeout nf_conntrack_udp_timeout_stream; do
              echo "$f = $($RTR cat /proc/sys/net/netfilter/$f)"; done > captures/$NAME.timeouts.txt
            iphone 60 ";answermode=auto;answerdelay=1000"; hphone 60 ";answermode=auto;answerdelay=1000"; sleep 3
            ctrack "2001 registered"; sleep 22; ctrack "25 s"; sleep 12; ctrack "37 s"
            ictl 0 dial sip:2001@lab.sip; sleep 8; ctrack "after the call 2002 -> 2001"
            ictl 0 hangup; sleep 2 ;;
  # 4.12: the nathelper fixes: REGISTER (received), an outbound call (Contact rewritten; 2002's BYE reaches 2001) and an
  # inbound call (sent to the received address; the 200's Contact rewritten); the SDP is not touched (one-way audio)
  nathelper)
            iphone 50 ";answermode=auto;answerdelay=1000"; hphone 50 ";answermode=auto;answerdelay=1000"; sleep 3
            ctrack "2001 registered"
            hctl 0 dial sip:2002@lab.sip; sleep 6; ctrack "call 2001 -> 2002 up"
            ictl 0 hangup; sleep 3
            ictl 0 dial sip:2001@lab.sip; sleep 6; ctrack "call 2002 -> 2001 up"
            hctl 0 hangup; sleep 3 ;;
  # 4.14: the call of 4.10 (2001 at home calls 2002) with nathelper and rtpengine: both directions of audio
  relay)    iphone 40 ";answermode=auto;answerdelay=1000"; hphone 40; sleep 3
            hctl 0 dial sip:2002@lab.sip; sleep 8; ctrack "call 2001 -> 2002 up"
            sessions
            ictl 4 hangup; sleep 3 ;;
  # 4.15: a STUN binding from home (the mapped address); a call with ICE candidates (baresip ice + coturn STUN);
  # a TURN allocation (a call with baresip's turn medianat)
  stun)     turn
            { echo "\$ turnutils_stunclient 192.0.2.30   (in the home namespace)"; $HM timeout 5 turnutils_stunclient 192.0.2.30 2>&1; } \
              > captures/$NAME.stunclient.txt
            # 2002 answers without ICE: on this box an ICE agent would list every address of the droplet as a host
            # candidate (its public one too); 2002 is the plain office phone of the other cases
            iphone 50 ";answermode=auto;answerdelay=1000"
            hphone 50 ";medianat=ice;stunserver=stun:192.0.2.30"; sleep 4
            hctl 0 dial sip:2002@lab.sip; sleep 8; ctrack "ICE call up"; hctl 0 hangup; sleep 3
            pkill -x baresip; sleep 1
            iphone 30 ";answermode=auto;answerdelay=1000"
            hphone 30 ";medianat=turn;stunserver=turn:192.0.2.30;stunuser=2001;stunpass=lab-turn-pass"; sleep 4
            hctl 0 dial sip:2002@lab.sip; sleep 8; ctrack "TURN call up"; hctl 0 hangup; sleep 3 ;;
  # 4.16: "I can hear them, they cannot hear me" (2002, in the office, calls 2001, who works from home): the server
  # fixes the signaling (nathelper) but not the media: 2001's 200 OK says c=192.168.1.21, 2002's RTP goes nowhere.
  # ticketfix: the same call with rtpengine
  ticket|ticketfix)
            iphone 40 ""; hphone 40 ";answermode=auto;answerdelay=1500"; sleep 3
            ictl 0 dial sip:2001@lab.sip; sleep 10; ctrack "call 2002 -> 2001 up"
            [ $CASE = ticketfix ] && sessions
            ictl 0 hangup; sleep 3 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; for p in baresip sipp dnsmasq rtpengine turnserver; do pkill -x $p 2>/dev/null; done
kill $TCPD $TCPH 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
iptables -t raw -D OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK 2>/dev/null
iptables -t raw -D OUTPUT -p udp -s 192.0.2.30 --sport 49160:49199 -j NOTRACK 2>/dev/null
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
{ echo "### the router's filter table at the end of the take (packets dropped: policy DROP counters)"; $RTR iptables -L -v -n
  echo; echo "### nat table"; $RTR iptables -t nat -L -v -n; } > captures/$NAME.router.txt 2>&1
./nat.sh down
[ $CASE = alg ] && { modprobe -r nf_nat_sip 2>/dev/null; modprobe -r nf_conntrack_sip 2>/dev/null; }
H="--enable-heuristic rtp_udp --enable-heuristic stun_udp"
for P in $NAME $NAME.home; do
  tshark -r captures/$P.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst \
    -e udp.dstport -e _ws.col.Info 2>/dev/null > captures/$P.txt
  tshark -r captures/$P.pcap $H -q -z rtp,streams 2>/dev/null > captures/$P.rtp.txt
  tshark -r captures/$P.pcap $H -Y "rtp or rtcp or icmp or stun" -T fields -e frame.number -e frame.time_relative \
    -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null > captures/$P.media.txt
done
[ $CASE = stun ] && tshark -r captures/$NAME.home.pcap $H -Y stun -V 2>/dev/null > captures/$NAME.stun.txt
# mask every eth0/eth1 IPv4 (the droplet's public address) in what this take wrote, in case a tool printed it
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
echo "=== internet side"; cat captures/$NAME.txt; echo "=== home side"; cat captures/$NAME.home.txt
echo "=== rtp (internet side)"; cat captures/$NAME.rtp.txt; echo "=== rtp (home side)"; cat captures/$NAME.home.rtp.txt
