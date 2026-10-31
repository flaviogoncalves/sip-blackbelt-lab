#!/bin/bash
# sip-lab takes for section 8 part A (troubleshooting field cases: the method, isolating a fault, hung calls, messages
# too large for UDP, audio impairments, echo, and the "video calls fail" ticket). Same plumbing as take-qosfax.sh.
#   sudo ./take-field.sh <case> <name>
# Cases (lesson):
#   method (8.1)          ticket "phone 2003 registers, but every call it makes gets 403": pjsua 2003 is set up with its
#                         own address as its domain (sip:2003@192.0.2.23, the From of every call); the proxy refuses
#                         a call whose From domain it does not serve (a lab rule, as most providers have: slide 162
#                         case 4); the fix = the phone's domain set to lab.sip; the same call again, answered
#   isolate (8.2)         terminal (<name>.terminal.txt): the ONE fault planted for this lesson is in the proxy: a
#                         "codec policy" line that deletes PCMU from every offer (codec_delete), while every phone is
#                         set to PCMU only, so every call through the proxy gets 488. The student pings from the
#                         phone's address, calls through the proxy (488), bypasses it (phone -> the provider, a SIPp
#                         UAS at 192.0.2.50: answered), calls phone to phone (answered), swaps the phone (pjsua 2003
#                         through the proxy: 488 again), then diffs the proxy's cfg and puts the last good one back
#                         (MI core:reload_routes): answered
#   hung (8.4)            a hung call: baresip 2001 calls baresip 2002 through the proxy (dialog module), hangs up,
#                         and its BYE is lost on the way (a tc filter on lo drops BYEs from 192.0.2.21 to the proxy;
#                         an NFLOG copy of the phone's SIP goes to <name>.phone.pcap first): 2001 is idle, 2002 still in the
#                         call, the proxy's dialog still confirmed (dialog:list in <name>.dlg.txt before and after)
#   hungping hungpingalive hungpingpj
#                         the dialog module's in-dialog OPTIONS pings to both sides (create_dialog flags
#                         options-ping-caller/-callee, options_ping_interval 10 s, a lab value; default 30). hungping:
#                         2001 hangs up as it leaves the network (from then on nothing to or from 192.0.2.21 arrives):
#                         the ping to it goes unanswered, the proxy ends the dialog and sends BYE both ways;
#                         hungpingalive: only the BYE is lost, 2001 is still there and answers the in-dialog OPTIONS
#                         200 for a call it no longer has: the pings never end the dialog; hungpingpj: the same with
#                         pjsua as 2001 (it answers 500); hungpj: the hung call with pjsua as 2001
#   hungrtp hungrtp0      the same hung call with the media through rtpengine (--timeout=10, a lab value), callee =
#                         a SIPp phone that sends no audio (a voicemail that only listens), so no media flows at all
#                         once 2001 has hung up; hungrtp: rtpengine tells OpenSIPS (--b2b-url, XMLRPC "teardown"
#                         -> mi_xmlrpc -> rtpengine:teardown = dialog:end_dlg) and the dialog module
#                         sends BYE both ways; hungrtp0: no --b2b-url, rtpengine only deletes its own session
#   hungsst               the same hung call between SIPp phones that agreed a session timer (RFC 4028,
#                         Session-Expires 30, refresher = caller; 30 s is a lab value, below RFC 4028's 90 s floor),
#                         the proxy enforcing it (sst module + dialog "bye-on-timeout"): no refresh comes, the session
#                         expires, the proxy sends BYE both ways
#   frag fragdrop big513 bigtcp (8.5)
#                         the phone is in its own network (namespace site, 198.51.100.121) behind a firewall
#                         (namespace edge: forwards, no NAT); every link MTU 1500. SIPp plays the customer's edge
#                         proxy forwarding a softphone's audio + video INVITE (call-av-hops.xml: 15 audio + 6 video
#                         formats, 3 Via headers), about 2 KB over UDP: frag = it leaves in two IP fragments, the
#                         proxy reassembles it, the call completes; fragdrop = the firewall drops non-first fragments
#                         (iptables -f -j DROP in edge): the INVITE never arrives (the proxy's kernel answers ICMP
#                         "fragment reassembly time exceeded" 30 s later) and the caller times out; big513 = the
#                         proxy refuses UDP requests over 1300 bytes with 513 Message Too Large (a lab rule: nothing
#                         on the box answers 413 or 513 by itself); bigtcp = the same INVITE over TCP (firewall still
#                         dropping fragments): the call completes
#   bigpjsua              pjsua 2001 in the site network (firewall dropping fragments), every codec it has, TCP on:
#                         its first INVITE (about 1.1 KB) goes over UDP, the one with credentials (over 1300 bytes)
#                         over TCP by itself (RFC 3261 18.1.1); the call completes
#   clean loss jitter jitterbig delay (8.6)
#                         baresip 2001 calls baresip 2002 through the proxy, 12 s of a 440 Hz tone; tc netem on 2001's
#                         media (lo, ports 30000-30015): none, loss 10%, delay 40ms 30ms (jitter), delay 100ms 80ms
#                         (more jitter than 2002's jitter buffer, baresip's default fixed 5-10 frames, holds), 400ms;
#                         jitternojb = the 40ms 30ms jitter to a 2002 with no jitter buffer (jitter_buffer_type off);
#                         2002's recording of what it played (<name>.2002.wav + .wav.txt) next to the RTP analysis
#   echo (8.7)            baresip 2001 (beeps: 200 ms of 1 kHz each second) calls a SIPp phone 2002 that sends back
#                         every RTP packet it receives (-rtp_echo), 200 ms late (netem on 2002's media): 2001's
#                         recording has its own beeps coming back; the echo is made at 2002, heard at 2001
#   ticket ticketfix (8.13)
#                         "calls with video or many codecs fail": the softphone (SIPp, call-av.xml) in the site
#                         network behind the firewall that drops IP fragments: its ~2 KB INVITE over UDP never
#                         arrives, the call never rings; a plain audio call (call.xml) from the same phone works;
#                         ticketfix = the softphone on TCP: the same video call rings and is answered
# Phones: 2001 = 192.0.2.21 (or 198.51.100.121 in the site network), 2002 = 192.0.2.22, 2003 = 192.0.2.23; the
# provider (isolate) = 192.0.2.50 (added to lab0 for the take).
# Writes captures/<name>.pcap (the proxy's side: lo, and the firewall's outside link in the site cases), .txt (SIP
# summary with time of day), .messages.txt (pcap_messages.py), .rtp.txt, .media.txt, every element's log (baresip
# logs with a time stamp per line; SIPp <tag>.msg.log from -trace_msg), .cfg.diff when lab.cfg changes, and per case:
# .phone.pcap (+ .phone.messages.txt), .dlg.txt, .rtpengine.txt, .site.pcap (+ .site.messages.txt), .frag.txt,
# .size.txt, .path.txt, .tcp.txt, .wav + .wav.txt, .rtcp.txt, .level.txt, .terminal.txt. Leaves nothing running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
for p in opensips baresip sipp pjsua rtpengine; do pkill -x $p 2>/dev/null; done; sleep 1
tc qdisc del dev lo root 2>/dev/null
ip netns del site 2>/dev/null; ip netns del edge 2>/dev/null; ip link del s8edge 2>/dev/null
mkdir -p /run/opensips
S=scenarios
B1=4401; B2=4402
ADDRS=(); IPT=(); HOLDERS=(); CAPS=()
rm -f captures/$NAME.*

# ---- lab.cfg as the take needs it ----
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
MODS=$'loadmodule "proto_udp.so"\n'
mods() { edit "$MODS" "$MODS"$'\n'"$1"; }   # mods <lines>: more modules after proto_udp
AUTH=$'\tif ($fd == "lab.sip") {\n'
RR=$'\trecord_route();\n\tif (!lookup("location")) {'
INDLG=$'\t\tif (loose_route()) {\n'
dialog() {  # dialog <create_dialog flags> [more modparam lines]: the dialog module tracks every call
  mods $'# section 8: the dialog module keeps every call it has seen until a BYE ends it (default_timeout 21600 s = 6 h)\nloadmodule "dialog.so"\n'"${2:-}"
  local call='create_dialog();'; [ -n "$1" ] && call="create_dialog(\"$1\");"
  edit "$RR" $'\tif (is_method("INVITE"))\n\t\t'"$call"$'\n'"$RR"
}
tcp() {  # the proxy listens on TCP too
  edit $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\nsocket=tcp:192.0.2.10:5060\n'
  mods $'loadmodule "proto_tcp.so"\n'
}
addr() { ip addr add "$1/32" dev lab0 2>/dev/null; ADDRS+=("$1"); }
ipt() {  # ipt <table> <chain> <rule...>: an iptables rule at the top of the chain, removed at the end of the take
  local t=$1 c=$2; shift 2
  iptables -t "$t" -I "$c" 1 "$@" && IPT+=("$(printf '%q ' "$t" "$c" "$@")")
}

case $CASE in
  # lesson 8.1 (a lab rule, as most providers have): a call whose From domain this proxy does not serve is refused
  method)
    edit "$AUTH" $'\t# lesson 8.1: a call whose From domain is not lab.sip is refused (a provider rule: slide 162, case 4)\n\tif (is_method("INVITE") && $fd != "lab.sip") {\n\t\txlog("L_NOTICE", "from-domain: INVITE from $si, From $fu: domain $fd is not served here: 403\\n");\n\t\tsend_reply(403, "Forbidden");\n\t\texit;\n\t}\n'"$AUTH" ;;
  # lesson 8.2: THE FAULT planted in the proxy (the only one): a line that deletes PCMU from every offer it relays
  isolate)
    edit "$RR" $'\t# carrier policy: offer the carrier PCMA only\n\tif (is_method("INVITE") && has_body("application/sdp"))\n\t\tcodec_delete("PCMU");\n'"$RR" ;;
  hung|hungpj) dialog "" ;;
  hungping|hungpingalive|hungpingpj) dialog "options-ping-caller,options-ping-callee" $'modparam("dialog", "options_ping_interval", 10)   # lab value (default 30 s)\n' ;;
  hungrtp|hungrtp0)
    dialog ""
    MI=''
    [ $CASE = hungrtp ] && MI=$'# lesson 8.4: rtpengine reaches the MI over XMLRPC (httpd + mi_xmlrpc) to end the dialog of a call whose media timed out\nloadmodule "httpd.so"\nmodparam("httpd", "ip", "127.0.0.1")\nmodparam("httpd", "port", 8888)\nloadmodule "mi_xmlrpc.so"\nmodparam("mi_xmlrpc", "http_root", "RPC2")\n'
    mods $'# lesson 8.4: the media through rtpengine\nloadmodule "rtpengine.so"\nmodparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")\n'"$MI"
    edit "$INDLG" $'\t\tif (is_method("BYE"))\n\t\t\trtpengine_delete();\t# the call is over: free the relay ports\n'"$INDLG"
    edit $'\tt_relay();\n}\n\n# the lab' $'\tif (is_method("INVITE") && has_body("application/sdp")) {\n\t\trtpengine_offer("replace-origin");\n\t\tt_on_reply("relay");\n\t}\n\tt_relay();\n}\n\n# lesson 8.4: the answer through rtpengine too\nonreply_route[relay] {\n\tif (has_body("application/sdp"))\n\t\trtpengine_answer("replace-origin");\n}\n\n# the lab' ;;
  hungsst)
    dialog "bye-on-timeout" $'# lesson 8.4: the session timer (RFC 4028) sets the dialog\'s lifetime: no refresh, the dialog expires, BYE both ways\nloadmodule "sst.so"\nmodparam("sst", "sst_flag", "SST_FLAG")\nmodparam("sst", "min_se", 30)   # lab value: RFC 4028 says no Min-SE below 90 s\n'
    edit $'\t\tcreate_dialog("bye-on-timeout");' $'\t\t{ setflag("SST_FLAG"); create_dialog("bye-on-timeout"); }' ;;
  frag|fragdrop|bigtcp|bigpjsua|ticket|ticketfix) tcp ;;
  big513)
    tcp
    edit $'\tif (has_totag()) {\n' $'\t# lesson 8.5 (a lab rule): a request over UDP longer than 1300 bytes is refused (RFC 3261 18.1.1 wants TCP above\n\t# 1300 bytes when the path MTU is unknown)\n\tif ($socket_in(proto) == "UDP" && $ml > 1300) {\n\t\txlog("L_NOTICE", "size: $rm from $si over UDP is $ml bytes: 513\\n");\n\t\tsend_reply(513, "Message Too Large");\n\t\texit;\n\t}\n\n\tif (has_totag()) {\n' ;;
  clean|loss|jitter|jitterbig|jitternojb|delay|echo) ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac
cmp -s $PLAIN $CFG || diff $PLAIN $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

# ---- helpers ----
stamp() {  # prefix every line with the time of day (ms), as a phone's own log would
  python3 -u -c 'import datetime, sys
for line in sys.stdin:
    sys.stdout.write(datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3] + " " + line)'
}
phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] [config lines "key value"...]: baresip with
  # a SIP trace (-s), RTP stats at hang-up, its recording in /tmp/baresip-<user>/received.wav, a time-stamped log
  local u=$1 ip=$2 ctrl=$3 rtp=$4 secs=$5 extra=${6:-} d kv; shift 6 2>/dev/null || shift $#
  d=$(./baresip-phone.sh "$u" "$ip" "$ctrl" "$rtp" "$extra")
  sed -i "s|^rtp_stats.*|rtp_stats\t\tyes|" "$d/config"
  for kv in "$@"; do   # a key replaced in place (baresip reads the first one) or added
    if grep -q "^#\?${kv%% *}[[:space:]]" "$d/config"; then sed -i "s|^#\?${kv%% *}[[:space:]].*|$kv|" "$d/config"
    else echo "$kv" >> "$d/config"; fi
  done
  (timeout "$secs" stdbuf -oL -eL baresip -f "$d" -t "$secs" -s 2>&1 | stamp > captures/$NAME.$u.log) &
}
ctl() { sleep "$1"; echo "$(date +%T.%3N) $2: $3 ${4:-}" >> captures/$NAME.ctl.log; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
uas() {  # uas <scenario> <seconds> <log tag> [sipp options]: SIPp phone 2002 at 192.0.2.22, one call
  local sc=$1 t=$2 tag=$3; shift 3
  timeout "$t" sipp -sf $S/$sc -s 2002 -i 192.0.2.22 -p 5060 -mi 192.0.2.22 -mp 40000 -m 1 -timeout "${t}s" -nostdin \
    -trace_msg -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 &
}
PJSUA_COMMON=(--null-audio --no-tcp --local-port 5060 --dis-codec "" --add-codec PCMU --use-timer 0 --log-level 5
              --app-log-level 3)
pjphone() {  # pjphone <user> <ip> <rtp-port> <seconds> <log tag> <sip id> [pjsua options]: pjsua driven by pj()
  local u=$1 ip=$2 rtp=$3 secs=$4 tag=$5 id=$6 fifo=/tmp/pjsua-$1.in; shift 6
  rm -f "$fifo"; mkfifo "$fifo"
  sleep "$secs" > "$fifo" & HOLDERS+=($!)
  timeout "$secs" stdbuf -oL pjsua --id "$id" --registrar sip:lab.sip --realm lab.sip --username "$u" \
    --password "lab-$u-pass" --ip-addr "$ip" --bound-addr "$ip" --rtp-port "$rtp" "${PJSUA_COMMON[@]}" \
    --log-file "captures/$NAME.$tag.log" "$@" < "$fifo" > "captures/$NAME.$tag.console.log" 2>&1 &
}
pj() {  # pj <delay> <user> <line> [line ...]: wait, then type these lines into that pjsua console
  sleep "$1"; local u=$2; shift 2
  timeout 2 bash -c 'printf "%s\n" "${@:2}" > "$1"' _ "/tmp/pjsua-$u.in" "$@" || echo "pj: $u is not running"
  echo "$(date +%T.%3N) pjsua $u: $*" >> captures/$NAME.ctl.log
}
mi() { opensips-cli -o fifo_file=/run/opensips/opensips_fifo -x mi "$@" 2>&1 | sed "s/\x1b\[[0-9;]*m//g"; }
dlg() {  # dlg <label>: the proxy's dialogs now, appended to <name>.dlg.txt
  { echo "## $(date +%T.%3N)  $1"; echo "\$ opensips-cli -x mi dialog:list"; mi dialog:list; echo; } >> captures/$NAME.dlg.txt
}
rtpe() {  # rtpe <label>: rtpengine's own list of calls (its CLI), appended to <name>.rtpengine.txt
  { echo "## $(date +%T.%3N)  $1"; echo "\$ rtpengine-ctl list sessions all"
    python3 -c 'import socket
s = socket.create_connection(("127.0.0.1", 9900), timeout=2); s.sendall(b"list sessions all\n")
out = b""
try:
    while True:
        d = s.recv(4096)
        if not d: break
        out += d
except socket.timeout: pass
print(out.decode(errors="replace").strip() or "(no sessions)")'; echo; } >> captures/$NAME.rtpengine.txt 2>&1
}
netem() {  # netem <source port base> <netem parameters...>: impair the UDP sent from those 16 ports, on lo
  local base=$1; shift
  tc qdisc add dev lo root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
  tc qdisc add dev lo parent 1:4 handle 40: netem "$@"
  tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport $base 0xfff0 flowid 1:4
  echo "\$ tc qdisc add dev lo parent 1:4 handle 40: netem $*   (UDP from ports $base-$((base + 15)) only)" > captures/$NAME.netem.txt
}
lose_bye() {  # every BYE that 2001 (192.0.2.21:5060) sends to the proxy is lost on the way, silently: a tc filter on lo
  # drops it after the phone's socket sent it (an iptables DROP in OUTPUT would make the phone's sendto() fail with
  # EPERM, and the phone would stop resending, which no real network does). The phone's own SIP, as it sent it, is
  # copied first by an iptables NFLOG rule into <name>.phone.pcap; the lo capture shows what reached the proxy.
  tc qdisc add dev lo root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
  tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip src 192.0.2.21/32 match ip dst 192.0.2.10/32 \
    match ip protocol 17 0xff match ip sport 5060 0xffff match u32 0x42594520 0xffffffff at 28 action drop
  { echo "# 2001's BYEs to the proxy are lost (tc on lo: UDP 192.0.2.21:5060 -> 192.0.2.10, payload starting 'BYE ')"
    tc filter show dev lo; } > captures/$NAME.lost.txt
  ipt filter OUTPUT -p udp -s 192.0.2.21 --sport 5060 -j NFLOG --nflog-group 21 --nflog-threshold 1   # each packet at once
  cap captures/$NAME.phone.pcap -i nflog:21
}
cut_off() {  # from now on nothing to or from 192.0.2.21 arrives: the phone left the network. What it sends is lost on
  # the way (tc on lo, as its BYEs); what is sent to it is lost on arrival (iptables INPUT, after the lo capture point,
  # so the proxy's capture shows what the proxy sent it)
  tc filter add dev lo parent 1: protocol ip prio 2 u32 match ip src 192.0.2.21/32 action drop
  ipt filter INPUT -d 192.0.2.21 -j DROP
  { echo; echo "# $(date +%T.%3N): 2001 cut off: every packet from 192.0.2.21 is lost (tc), every packet to it too"
    echo "# (iptables -I INPUT -d 192.0.2.21 -j DROP)"; tc filter show dev lo; } >> captures/$NAME.lost.txt
}
cap() {  # cap <file> <tcpdump args...>: a capture that runs until the end of the take
  tcpdump -U -s 0 -w "$@" 2>/dev/null & CAPS+=($!)
}
T=captures/$NAME.terminal.txt
term() {  # term <command>: typed as user lab in ~/lab; the prompt, the command and its output go to the terminal file
  printf 'lab@sip-lab-2:~/lab$ %s\n' "$1" >> $T
  env -i HOME=/home/lab USER=lab LOGNAME=lab PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    setpriv --reuid=lab --regid=lab --init-groups bash -c "cd /home/lab/lab; $1" 2>&1 | sed "s/\x1b\[[0-9;]*m//g" >> $T
}
note() { printf '%s\n' "$1" >> $T; }   # a line the student does not type (a pause, what runs elsewhere)

# the site network (lessons 8.5, 8.13): phone 198.51.100.121 in namespace site -> firewall (namespace edge, a router:
# no NAT) -> the internet side (the root namespace, the proxy 192.0.2.10). Every link is a veth with MTU 1500.
#   site s8site 198.51.100.121/25 -- s8lan 198.51.100.1/25  edge  s8wan 198.51.100.130/25 -- s8edge 198.51.100.129/25 root
site_up() {
  local E="ip netns exec edge" P="ip netns exec site"
  ip netns add site; ip netns add edge
  ip link add s8edge type veth peer name s8wan; ip link set s8wan netns edge
  ip link add s8site type veth peer name s8lan; ip link set s8site netns site; ip link set s8lan netns edge
  echo 1 > /proc/sys/net/ipv6/conf/s8edge/disable_ipv6
  ip addr add 198.51.100.129/25 dev s8edge; ip link set s8edge up
  ip route add 198.51.100.0/25 via 198.51.100.130 dev s8edge
  ipt filter INPUT -i s8edge -j ACCEPT   # ufw drops everything that is not on lo
  $E sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 1 > /proc/sys/net/ipv4/ip_forward'
  $E ip link set lo up
  $E ip addr add 198.51.100.1/25 dev s8lan; $E ip link set s8lan up
  $E ip addr add 198.51.100.130/25 dev s8wan; $E ip link set s8wan up
  $E ip route add default via 198.51.100.129
  $P sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
  $P ip link set lo up
  $P ip addr add 198.51.100.121/25 dev s8site; $P ip link set s8site up
  $P ip route add default via 198.51.100.1
  { echo "# the path from the phone to the proxy: every link and its MTU"
    echo "\$ ip -n site -br link; ip -n edge -br link; ip -br link show s8edge"
    for ns in site edge; do ip -n $ns -o link | awk -v ns=$ns '{print ns": "$2" "$4" "$5}'; done
    ip -o link show s8edge | awk '{print "root: "$2" "$4" "$5}'
    echo "\$ ip netns exec site ip route get 192.0.2.10"; $P ip route get 192.0.2.10
    echo "\$ ip netns exec site ping -c 2 -M do -s 1472 192.0.2.10   (1472 + 8 UDP/ICMP + 20 IP = 1500: fits, no fragment)"
    $P ping -c 2 -W 1 -M do -s 1472 192.0.2.10 | tail -n 3
    echo "\$ ip netns exec site ping -c 2 -M do -s 1473 192.0.2.10   (one byte more, Don't Fragment set)"
    $P ping -c 2 -W 1 -M do -s 1473 192.0.2.10 2>&1 | grep -v -E "^PING|^$|statistics"; } > captures/$NAME.path.txt
}
site_down() {
  ip netns pids site 2>/dev/null | xargs -r kill 2>/dev/null; ip netns pids edge 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 1; ip link del s8edge 2>/dev/null; ip netns del site 2>/dev/null; ip netns del edge 2>/dev/null
}
site_sipp() {  # site_sipp <scenario> <seconds> <log tag> <transport u1|t1> [sipp options]: the phone (SIPp) in site
  local sc=$1 t=$2 tag=$3 tr=$4; shift 4
  ip netns exec site timeout "$t" sipp 192.0.2.10:5060 -sf $S/$sc -s 2001 -set callee 2002 -auth_uri 2002@lab.sip \
    -au 2001 -ap lab-2001-pass -i 198.51.100.121 -p 5060 -t "$tr" -m 1 -timeout "${t}s" -nostdin -trace_msg \
    -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 || echo "$tag: sipp ended with an error"
}
fwdrop() {  # the site's firewall drops every IP fragment but the first (the lesson's fault on the path)
  ip netns exec edge iptables -A FORWARD -f -j DROP
  { echo "# the firewall (namespace edge): every IP fragment but the first is dropped"
    echo "\$ ip netns exec edge iptables -A FORWARD -f -j DROP"; } >> captures/$NAME.path.txt
}

# ---- media relay (hungrtp*) and the proxy ----
RTPE=(rtpengine --config-file=none --interface=192.0.2.10 --listen-ng=127.0.0.1:2223 --listen-cli=127.0.0.1:9900
      --port-min=35000 --port-max=35099 --table=-1 --foreground --log-stderr --log-level=6 --pidfile=/tmp/rtpengine.pid
      --timeout=10)
[ $CASE = hungrtp ] && RTPE+=(--b2b-url=http://127.0.0.1:8888/RPC2 --xmlrpc-format=1)
if [[ $CASE == hungrtp* ]]; then
  ipt raw OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK   # rtpengine's own sockets, as SIPp's (net.sh)
  echo "${RTPE[*]}" > captures/$NAME.rtpengine-cmdline.txt
  rtpengine --help 2>&1 | grep -E -- "--(timeout|silent-timeout|final-timeout|offer-timeout|b2b-url|xmlrpc-format|delete-delay)=" \
    > captures/$NAME.rtpengine-help.txt
  "${RTPE[@]}" 2>&1 | stamp > captures/$NAME.rtpengine.log & sleep 1   # before OpenSIPS: it pings rtpengine at start
fi
/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & sleep 2
case $CASE in
  frag|fragdrop|big513|bigtcp|bigpjsua|ticket|ticketfix)
    site_up
    cap captures/$NAME.lo.pcap -i lo
    cap captures/$NAME.wan.pcap -i s8edge                         # the proxy's side of the firewall
    ip netns exec edge tcpdump -U -s 0 -w captures/$NAME.site.pcap -i s8lan 2>/dev/null & CAPS+=($!)   # the phone's side
    ;;
  *) cap captures/$NAME.pcap -i lo 'udp or icmp or tcp port 5060' ;;
esac
sleep 1

# ---- the cases ----
case $CASE in
  method)
    phone 2002 192.0.2.22 $B2 40000 40 ";answermode=auto;answerdelay=1000"
    # the ticket as reported: 2003 registers fine (the REGISTER goes to sip:lab.sip), but its identity, and so the
    # From of every call, is sip:2003@192.0.2.23: the phone's own address where the domain belongs
    pjphone 2003 192.0.2.23 50000 14 2003-before sip:2003@192.0.2.23; sleep 4
    pj 0 2003 m sip:2002@lab.sip; sleep 4
    pj 0 2003 q; sleep 3
    # the fix: the phone's domain set to lab.sip; the same call again
    pjphone 2003 192.0.2.23 50000 20 2003-after sip:2003@lab.sip; sleep 4
    pj 0 2003 m sip:2002@lab.sip; sleep 6
    pj 0 2003 h; sleep 2; pj 0 2003 q; sleep 2 ;;
  isolate)
    addr 192.0.2.50
    PH=";audio_codecs=PCMU/8000/1"   # every phone of this office is set to G.711 mu-law only
    phone 2002 192.0.2.22 $B2 40000 100 "$PH;answermode=auto;answerdelay=1000"
    phone 2001 192.0.2.21 $B1 30000 100 "$PH"
    pjphone 2003 192.0.2.23 50000 100 2003 sip:2003@lab.sip
    timeout 100 sipp -sf $S/uas-pcmu.xml -s provider -i 192.0.2.50 -p 5060 -mi 192.0.2.50 -mp 6000 -m 1 -timeout 100s \
      -nostdin -trace_msg -message_file captures/$NAME.provider.msg.log > captures/$NAME.provider.log 2>&1 &
    sleep 4
    note "# The ticket: \"no call goes through since this morning; the phones show 'not acceptable'\". Running already"
    note "# (not typed): OpenSIPS (the proxy, 192.0.2.10) with the cfg it runs today, /tmp/lab-take.cfg; baresip phones"
    note "# 2001 (192.0.2.21, control port 4401) and 2002 (192.0.2.22, answers by itself), both set to PCMU only;"
    note "# pjsua 2003 (192.0.2.23, PCMU only) in another terminal; a SIPp phone at the provider, 192.0.2.50."
    note "# Start from the middle (slide 154): can the phone's address reach the proxy at all?"
    term "ping -c 3 -I 192.0.2.21 192.0.2.10 | tail -n 2"
    note "# Layers 1 to 3 work. Now the call as the user makes it: 2001 -> proxy -> 2002."
    term "./bctl.py 4401 dial sip:2002@lab.sip >/dev/null"; sleep 5
    term "grep -E 'Call established|session closed|Not Acceptable' captures/$NAME.2001.log | tail -n 1 | cut -c1-110"
    term "grep 'no common' captures/$NAME.2002.log | tail -n 1 | cut -c1-110"
    note "# Simplify (slide 155): bypass the proxy, the phone straight to the provider."
    term "./bctl.py 4401 dial sip:+441614960142@192.0.2.50 >/dev/null"; sleep 4
    term "grep -E 'Call established|session closed' captures/$NAME.2001.log | tail -n 1 | cut -c1-110"
    term "./bctl.py 4401 hangup >/dev/null"; sleep 2
    note "# Bypass the provider too: phone to phone."
    term "./bctl.py 4401 dial sip:2002@192.0.2.22 >/dev/null"; sleep 4
    term "grep -E 'Call established|session closed' captures/$NAME.2001.log | tail -n 1 | cut -c1-110"
    term "./bctl.py 4401 hangup >/dev/null"; sleep 2
    note "# Both phones and the network work without the proxy. Switch one component (slide 156): another phone"
    note "# through the proxy. In the pjsua 2003 terminal, typed: m, then sip:2002@lab.sip"
    pj 0 2003 m sip:2002@lab.sip; sleep 5
    term "grep -E 'DISCONNECTED|CONFIRMED' captures/$NAME.2003.console.log | tail -n 1 | cut -c1-110"
    note "# Two phones fail the same way through the proxy, and nothing fails without it: the proxy is the suspect."
    note "# What changed in it? Compare the cfg it runs with the last good one (lab.cfg, digest algorithm filled in):"
    term "diff <(sed 's/@DIGEST_ALGS@/MD5/' opensips/lab.cfg) /tmp/lab-take.cfg"
    note "# Put the last good cfg back and reload the script's routes (the registrations stay in memory):"
    term "sudo cp /tmp/lab-take-plain.cfg /tmp/lab-take.cfg && opensips-cli -o fifo_file=/run/opensips/opensips_fifo -x mi core:reload_routes"
    sleep 1
    term "./bctl.py 4401 dial sip:2002@lab.sip >/dev/null"; sleep 5
    term "grep -E 'Call established|session closed' captures/$NAME.2001.log | tail -n 1 | cut -c1-110"
    term "./bctl.py 4401 hangup >/dev/null"; sleep 2
    pj 0 2003 q; sleep 1 ;;
  hung|hungping|hungpingalive|hungpj|hungpingpj)
    lose_bye
    PH=";audio_codecs=PCMU/8000/1"
    phone 2002 192.0.2.22 $B2 40000 90 "$PH;answermode=auto;answerdelay=1000"
    if [[ $CASE == *pj ]]; then   # the caller is pjsua 2001 (it resends its BYE, RFC 3261 timer E)
      pjphone 2001 192.0.2.21 30000 90 2001 sip:2001@lab.sip; sleep 3
      pj 0 2001 m sip:2002@lab.sip
      sleep 5; dlg "1. the call is up (5 s after 2001 dialled)"
      pj 0 2001 h
    else                          # the caller is baresip 2001
      phone 2001 192.0.2.21 $B1 30000 90 "$PH"; sleep 3
      ctl 0 $B1 dial sip:2002@lab.sip
      sleep 5; dlg "1. the call is up (5 s after 2001 dialled)"
      [ $CASE = hungping ] && cut_off   # 2001 hangs up as its network goes: nothing to or from it arrives any more
      ctl 0 $B1 hangup
    fi
    # 2001 has hung up: its BYE is lost on the way to the proxy
    if [[ $CASE == hung || $CASE == hungpj ]]; then
      sleep 6; dlg "2. 6 s after 2001 hung up (the proxy has not seen its BYE)"
      sleep 34; dlg "3. 40 s after 2001 hung up"
      ctl 0 $B2 listcalls; [[ $CASE == hung ]] && ctl 0 $B1 listcalls
      ctl 0 $B2 hangup; sleep 3; dlg "4. after 2002 hangs up too (its BYE passes; 2001 answers it)"
    else
      sleep 6; dlg "2. 6 s after 2001 hung up"
      sleep 19; dlg "3. 25 s after 2001 hung up"
      sleep 20; dlg "4. 45 s after 2001 hung up"
      ctl 0 $B2 listcalls; [[ $CASE != *pj ]] && ctl 0 $B1 listcalls
    fi
    sleep 1 ;;
  hungrtp|hungrtp0)
    lose_bye
    sipp_reg 2002 192.0.2.22
    uas uas-pcmu.xml 60 2002   # the voicemail: answers, listens, sends no audio
    phone 2001 192.0.2.21 $B1 30000 60 ";audio_codecs=PCMU/8000/1"; sleep 3
    ctl 0 $B1 dial sip:2002@lab.sip
    sleep 5; dlg "1. the call is up (5 s after 2001 dialled)"; rtpe "1. the call is up"
    ctl 0 $B1 hangup   # BYE lost; 2001 stops sending; 2002 never sent: no media at all from here
    sleep 6; dlg "2. 6 s after 2001 hung up (no media for 6 s)"; rtpe "2. 6 s after 2001 hung up"
    sleep 14; dlg "3. 20 s after 2001 hung up (rtpengine --timeout=10 has passed)"; rtpe "3. 20 s after 2001 hung up"
    sleep 2 ;;
  hungsst)
    lose_bye
    sipp_reg 2002 192.0.2.22
    uas uas-sst.xml 60 2002 -set se 30; sleep 1
    timeout 60 sipp 192.0.2.10:5060 -sf $S/call-sst.xml -s 2001 -set callee 2002 -set se 30 -auth_uri 2002@lab.sip \
      -au 2001 -ap lab-2001-pass -i 192.0.2.21 -p 5060 -mi 192.0.2.21 -mp 30000 -m 1 -timeout 60s -max_retrans 30 \
      -nostdin -trace_msg -message_file captures/$NAME.2001.msg.log > captures/$NAME.2001.log 2>&1 &
    sleep 4; dlg "1. the call is up (the 200 OK says Session-Expires: 30;refresher=uac)"
    sleep 6; dlg "2. 5 s after 2001 hung up (its BYE lost, no refresh will come)"
    sleep 30; dlg "3. 35 s after 2001 hung up (the session has expired)"
    sleep 2 ;;
  frag|big513|fragdrop|ticket)
    [ $CASE = fragdrop ] || [ $CASE = ticket ] && fwdrop
    sipp_reg 2002 192.0.2.22
    SC=call-av-hops.xml; [ $CASE = ticket ] && SC=call-av.xml
    W=20; [ $CASE = fragdrop ] || [ $CASE = ticket ] && W=40
    uas uas-av.xml $((W + 2)) 2002; sleep 1
    site_sipp $SC $W 2001 u1
    if [ $CASE = fragdrop ] || [ $CASE = ticket ]; then
      sleep 4   # the proxy's kernel gives up the last half-received INVITE 30 s after its first fragment
    fi
    if [ $CASE = ticket ]; then   # the same phone, a plain audio call: a small INVITE
      pkill -x sipp; sleep 2   # the video call's callee is still waiting: it never got the INVITE
      uas uas-pcmu.xml 20 2002-audio; sleep 1
      site_sipp call.xml 15 2001-audio u1
    fi
    sleep 1 ;;
  bigtcp|ticketfix)
    fwdrop
    sipp_reg 2002 192.0.2.22
    SC=call-av-hops.xml; [ $CASE = ticketfix ] && SC=call-av.xml
    uas uas-av.xml 22 2002; sleep 1
    site_sipp $SC 20 2001 t1
    sleep 1 ;;
  bigpjsua)
    # pjsua 2001 in the site network with every codec it has and TCP on: RFC 3261 18.1.1, done by the phone itself
    fwdrop
    sipp_reg 2002 192.0.2.22
    uas uas-pcmu.xml 20 2002; sleep 1
    rm -f /tmp/pjsua-2001.in; mkfifo /tmp/pjsua-2001.in
    (sleep 3; echo m; echo sip:2002@lab.sip; sleep 5; echo h; sleep 2; echo q) > /tmp/pjsua-2001.in &
    ip netns exec site timeout 16 stdbuf -oL pjsua --id sip:2001@lab.sip --registrar sip:lab.sip --realm lab.sip \
      --username 2001 --password lab-2001-pass --ip-addr 198.51.100.121 --bound-addr 198.51.100.121 --local-port 5060 \
      --null-audio --use-timer 0 --log-level 5 --app-log-level 3 --log-file captures/$NAME.2001.log \
      < /tmp/pjsua-2001.in > captures/$NAME.2001.console.log 2>&1
    grep -E "TX [0-9]+ bytes Request msg" captures/$NAME.2001.log | sed -E 's/ \(tdta[^)]*\)//' > captures/$NAME.2001.tx.txt
    sleep 1 ;;
  clean|loss|jitter|jitterbig|jitternojb|delay)
    PH=";audio_codecs=PCMU/8000/1"
    JB=(); [ $CASE = jitternojb ] && JB=("jitter_buffer_type off")   # a phone without a jitter buffer
    phone 2002 192.0.2.22 $B2 40000 30 "$PH;answermode=auto;answerdelay=500" "${JB[@]}"
    phone 2001 192.0.2.21 $B1 30000 30 "$PH"; sleep 3
    case $CASE in   # on 2001's media only (RTP 30000, RTCP 30001): what 2002 receives
      loss)   netem 30000 loss 10% ;;
      jitter|jitternojb) netem 30000 delay 40ms 30ms ;;
      jitterbig) netem 30000 delay 100ms 80ms ;;   # more jitter than the phone's buffer holds
      delay)  netem 30000 delay 400ms ;;
    esac
    ctl 0 $B1 dial sip:2002@lab.sip; ctl 13 $B1 hangup; sleep 2
    [ $CASE = clean ] || { tc -s qdisc show dev lo >> captures/$NAME.netem.txt; tc qdisc del dev lo root; } ;;
  echo)
    # 20 s of beeps (200 ms of 1 kHz at the start of every second) as 2001's microphone, at 48 kHz as ausrc_srate
    python3 - /tmp/lab-beeps.wav <<'EOF'
import math, struct, sys, wave
rate = 48000
s = [int(9000 * math.sin(2 * math.pi * 1000 * n / rate)) if (n % rate) < rate // 5 else 0 for n in range(20 * rate)]
with wave.open(sys.argv[1], "wb") as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate); w.writeframes(struct.pack(f"<{len(s)}h", *s))
EOF
    sipp_reg 2002 192.0.2.22
    uas uas-pcmu.xml 30 2002 -rtp_echo   # sends every RTP packet it gets back to its sender
    netem 40000 delay 200ms              # ... 200 ms late (2002's media ports only)
    phone 2001 192.0.2.21 $B1 30000 30 ";audio_codecs=PCMU/8000/1" "audio_source aufile,/tmp/lab-beeps.wav"; sleep 3
    ctl 0 $B1 dial sip:2002@lab.sip; ctl 13 $B1 hangup; sleep 2
    tc -s qdisc show dev lo >> captures/$NAME.netem.txt; tc qdisc del dev lo root ;;
esac

# ---- the end: stop everything, then read the captures ----
sleep 1
for p in baresip sipp pjsua; do pkill -x $p 2>/dev/null; done
[[ $CASE == hungrtp* ]] && pkill -x rtpengine
for p in "${HOLDERS[@]}"; do kill "$p" 2>/dev/null; done; rm -f /tmp/pjsua-*.in /tmp/lab-beeps.wav
sleep 1; kill "${CAPS[@]}" 2>/dev/null; sleep 1; pkill -x opensips; sleep 1
site_down
for r in "${IPT[@]}"; do eval "set -- $r"; t=$1 c=$2; shift 2; iptables -t "$t" -D "$c" "$@"; done
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
tc qdisc del dev lo root 2>/dev/null
cp /tmp/baresip-2002/received.wav captures/$NAME.2002.wav 2>/dev/null
[ $CASE = echo ] && cp /tmp/baresip-2001/received.wav captures/$NAME.2001.wav

R="-o rtp.heuristic_rtp:TRUE"
if [ -f captures/$NAME.wan.pcap ]; then   # the proxy's view = lo + its side of the firewall
  mergecap -w captures/$NAME.pcap captures/$NAME.lo.pcap captures/$NAME.wan.pcap && rm -f captures/$NAME.lo.pcap captures/$NAME.wan.pcap
fi
summary() {  # summary <pcap>: every SIP message, frame number, time from the start and time of day, addresses
  tshark -r "$1" -t a -Y sip -T fields -e frame.number -e frame.time_relative -e _ws.col.Time -e ip.src -e ip.dst \
    -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null | sed -E 's/\t([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3})[0-9]*\t/\t\1\t/'
}
summary captures/$NAME.pcap > captures/$NAME.txt
tshark -r captures/$NAME.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap $R -Y "rtp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type -e rtp.seq -e _ws.col.Protocol -e _ws.col.Info \
  2>/dev/null > captures/$NAME.media.txt
python3 pcap_messages.py captures/$NAME.pcap >/dev/null
for side in phone site; do
  [ -f captures/$NAME.$side.pcap ] || continue
  summary captures/$NAME.$side.pcap > captures/$NAME.$side.txt
  python3 pcap_messages.py captures/$NAME.$side.pcap >/dev/null
done
case $CASE in
  frag|fragdrop|big513|bigtcp|bigpjsua|ticket|ticketfix)
    { for side in site pcap; do
        f=captures/$NAME.$side.pcap; [ $side = pcap ] && f=captures/$NAME.pcap
        [ $side = site ] && echo "# the phone's side of the firewall ($NAME.site.pcap): every IP fragment and every ICMP" \
                         || echo "# the proxy's side ($NAME.pcap: the firewall's outside link + lo): every IP fragment and every ICMP"
        echo "# frame, time, source, destination, IP id, more-fragments flag, fragment offset (8-byte units: 185 = byte 1480), IP total length, info"
        tshark -r $f -o ip.defragment:FALSE -Y "ip.flags.mf == 1 or ip.frag_offset > 0 or icmp" -T fields \
          -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.id -e ip.flags.mf -e ip.frag_offset -e ip.len \
          -e _ws.col.Info 2>/dev/null
        echo
      done; } > captures/$NAME.frag.txt
    { echo "# the size of every SIP request and reply as it crossed each side (UDP payload or TCP message, bytes)"
      for side in site pcap; do
        f=captures/$NAME.$side.pcap; [ $side = pcap ] && f=captures/$NAME.pcap
        echo "## $f"
        tshark -r $f -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e udp.length \
          -e tcp.len -e tcp.reassembled.length -e _ws.col.Info 2>/dev/null | awk -F'\t' '{
            n = ($5 != "") ? $5 - 8 : (($7 != "") ? $7 : $6); proto = ($5 != "") ? "UDP" : "TCP"
            printf "%5s %8.3f  %-15s -> %-15s %s %5d bytes  %s\n", $1, $2, $3, $4, proto, n, substr($8, 1, 70) }'
      done; } > captures/$NAME.size.txt
    if [ $CASE = bigtcp ] || [ $CASE = ticketfix ] || [ $CASE = bigpjsua ]; then   # the TCP legs as one text stream each (pcap_messages.py reads UDP)
      for f in site pcap; do
        p=captures/$NAME.$f.pcap; [ $f = pcap ] && p=captures/$NAME.pcap
        for s in $(tshark -r $p -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e tcp.stream 2>/dev/null); do
          echo "## $p, TCP stream $s"; tshark -r $p -q -z follow,tcp,ascii,$s 2>/dev/null
        done
      done > captures/$NAME.tcp.txt
    fi ;;
  clean|loss|jitter|jitterbig|jitternojb|delay)
    python3 wav_summary.py --tone 440 captures/$NAME.2002.wav > captures/$NAME.2002.wav.txt 2>&1
    tshark -r captures/$NAME.pcap $R -o rtcp.show_roundtrip_calculation:TRUE -Y rtcp -T fields -e frame.number \
      -e frame.time_relative -e ip.src -e ip.dst -e rtcp.pt -e rtcp.ssrc.fraction -e rtcp.ssrc.cum_nr \
      -e rtcp.ssrc.jitter -e rtcp.roundtrip-delay 2>/dev/null > captures/$NAME.rtcp.txt ;;
  echo)
    python3 wav_summary.py --onsets captures/$NAME.2001.wav > captures/$NAME.2001.wav.txt 2>&1
    python3 rtp_level.py captures/$NAME.pcap > captures/$NAME.level.txt 2>&1 ;;
esac
# phones may log the droplet's public address: mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
chown -R lab:lab captures
grep -v -E "REGISTER|401 Unauth" captures/$NAME.txt
