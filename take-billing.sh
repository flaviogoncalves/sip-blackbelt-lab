#!/bin/bash
# sip-lab takes for section 8 part B (billing: CDR counts, durations, hung calls, dialers, a reconciliation ticket) and
# the NAT final ticket (8.12).
#   sudo ./take-billing.sh <case> <name>
# Cases (lesson): count (8.8), duration (8.9), hungbill (8.10), ticket ticketfix ticketfix5 (8.11), nat natfix (8.12).
#
# The billing cases have two sides, each with its own CDRs: OUR proxy (lab.cfg + acc, 192.0.2.10, the customer's side)
# and THE CARRIER (opensips/carrier.cfg + acc, 192.0.2.40) with the far end behind it (SIPp, 192.0.2.50: the called
# people). The carrier and the far end live in their own network namespace ("carrier"), reached through a router
# namespace ("transit") that plays the network between the two companies: that is where the takes lose packets
# (iptables in transit's FORWARD chain), so each side's capture shows only what reached it:
#   root (ours): proxy 192.0.2.10, callers 192.0.2.21 (2001) and .23 (2003, the dialer); veth billnet 198.51.100.129/30
#   transit:     tr 198.51.100.130/30 (toward us), tc 198.51.100.133/30 (toward the carrier); forwards, no NAT
#   carrier:     cwan 198.51.100.134/30; 192.0.2.40 (the carrier's OpenSIPS) and 192.0.2.50 (the far end) on its lo
# Callers are SIPp (scenarios/bill-uac.xml, dialer-uac.xml); the far end is SIPp (scenarios/uas-bill.xml). Numbers are
# Ofcom drama ranges (fictitious): our customer acme holds +44 20 7946 0100-0199 (2001 = 0101, 2003 = 0103); the far end
# numbers are +44 161 496 01xx (0100 answers at once, 0999 is an announcement in early media that never answers).
# CDRs: acc with the dialog module ("cdr|failed"), written by db_flatstore: ours in /tmp/lab-acc, the carrier's in
# /tmp/lab-cacc, one line per call: method|from_tag|to_tag|callid|sip_code|sip_reason|time|caller|callee|answered_at|
# ended_at|setuptime|created|duration|ms_duration (answered_at, ended_at: when that side saw the 200 OK and the BYE, to
# the microsecond). Each case writes captures/<name>.pcap (our side: lo + billnet) and <name>.carrier.pcap
# (the carrier's namespace), .txt (SIP summary with absolute times), .messages.txt, .carrier.messages.txt, the logs and
# SIPp message logs of every element, .cfg.diff / .carrier.cfg.diff, .ours.cdr / .carrier.cdr (the raw CDR lines),
# .cdr.txt (both sets with a header), .compare.txt (cdr_compare.py), .faults.txt (what the network did: the transit
# rules and their counters), .dlg.txt (dlg_list on both sides at moments of the take).
#
# nat / natfix (8.12) use the NAT of nat.sh instead (phone 2001 at home behind a router, 2002 on the internet side):
# captures <name>.pcap (internet side) and <name>.home.pcap (the home side of the router), .conntrack.txt, .router.txt.
#
# Leaves nothing running: the namespaces, veths, routes, iptables rules, faketime processes, SIPp and OpenSIPS are
# removed, lab.cfg and carrier.cfg are untouched (the take edits copies in /tmp).
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
for p in opensips baresip sipp dnsmasq; do pkill -x $p 2>/dev/null; done; sleep 1
mkdir -p /run/opensips
S=scenarios
C="ip netns exec carrier"; X="ip netns exec transit"
rm -f captures/$NAME.*

billnet() {  # billnet up|down: the carrier's namespace and the network between the two companies
  ip netns del carrier 2>/dev/null; ip netns del transit 2>/dev/null; ip link del billnet 2>/dev/null
  while iptables -D INPUT -i billnet -j ACCEPT 2>/dev/null; do :; done
  [ "$1" = down ] && return 0
  ip netns add transit; ip netns add carrier
  ip link add billnet type veth peer name tr netns transit
  $X ip link add tc type veth peer name cwan netns carrier
  echo 1 > /proc/sys/net/ipv6/conf/billnet/disable_ipv6
  ip addr add 198.51.100.129/30 dev billnet; ip link set billnet up
  ip route replace 192.0.2.40/32 via 198.51.100.130 src 192.0.2.10
  ip route replace 192.0.2.50/32 via 198.51.100.130 src 192.0.2.10
  iptables -I INPUT -i billnet -j ACCEPT   # ufw drops everything that is not on lo
  $X sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 1 > /proc/sys/net/ipv4/ip_forward'
  $X ip link set lo up
  $X ip addr add 198.51.100.130/30 dev tr; $X ip link set tr up
  $X ip addr add 198.51.100.133/30 dev tc; $X ip link set tc up
  $X ip route add 192.0.2.40/32 via 198.51.100.134; $X ip route add 192.0.2.50/32 via 198.51.100.134
  $X ip route add 192.0.2.0/24 via 198.51.100.129
  $C sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
  $C ip link set lo up; $C ip addr add 192.0.2.40/32 dev lo; $C ip addr add 192.0.2.50/32 dev lo
  $C ip addr add 198.51.100.134/30 dev cwan; $C ip link set cwan up
  $C ip route add default via 198.51.100.133
}
# the network's faults, in transit's FORWARD chain: toward us = from the carrier to our proxy, toward the carrier = ours
TO_US="-i tc -o tr"; TO_CARRIER="-i tr -o tc"
lose() {  # lose <to_us|to_carrier> <label> [iptables matches]: drop what matches in that direction, until unlose
  local dir=$TO_US; [ "$1" = to_carrier ] && dir=$TO_CARRIER
  $X iptables -A FORWARD $dir -p udp "${@:3}" -m comment --comment "$2" -j DROP
  echo "$(stamp) lose $1: $2 (iptables -A FORWARD $dir -p udp ${*:3} -j DROP)" >> captures/$NAME.faults.txt
}
unlose() {  # unlose <label>: remove the rule with that comment, keeping its counter in faults.txt
  local line; line=$($X iptables -L FORWARD -v -n -x --line-numbers | grep -F "/* $1 */" | head -1)
  echo "$(stamp) restore: $1 ($(echo "$line" | awk '{print $2}') packets dropped)" >> captures/$NAME.faults.txt
  [ -n "$line" ] && $X iptables -D FORWARD "$(echo "$line" | awk '{print $1}')"
}
stamp() { date +%H:%M:%S.%3N; }

# the two configs as the take needs them
CFG=/tmp/lab-take.cfg; sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > $CFG
PLAIN=/tmp/lab-take-plain.cfg; cp $CFG $PLAIN
CCFG=/tmp/lab-carrier.cfg; cp opensips/carrier.cfg $CCFG
editf() {  # editf <file> <old> <new>: replace the first <old> (fails loudly if <old> is missing)
  python3 - "$1" "$2" "$3" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if old not in s:
    sys.exit(f"cfg edit ({p}): {old!r} not found")
open(p, "w").write(s.replace(old, new, 1))
EOF
}
edit() { editf $CFG "$1" "$2"; }     # our proxy (lab.cfg)
cedit() { editf $CCFG "$1" "$2"; }   # the carrier
MODS=$'loadmodule "proto_udp.so"\n'

# ---- our proxy: calls to numbers leave through the carrier trunk, with a CDR each ----
ACC_MODS=$'\n# section 8: a CDR per call (acc with the dialog module), written by db_flatstore to /tmp/lab-acc/acc_*.log\nloadmodule "dialog.so"\nloadmodule "db_flatstore.so"\nloadmodule "acc.so"\nmodparam("acc", "db_url", "flatstore:/tmp/lab-acc")\nmodparam("acc", "extra_fields", "db: caller; callee; answered_at; ended_at")\n'
TRUNK_ARM=$'\t# section 8: a call to a telephone number leaves through the carrier trunk\n\tif (is_method("INVITE") && $rU =~ "^[+0-9][-+0-9.()]{6,}$") {\n\t\troute(outbound);\n\t\texit;\n\t}\n\n'
OUT_ROUTE=$'\n# section 8: a call to a telephone number: digest, our caller ID, a CDR, out to the carrier (IP trunk)\nroute[outbound] {\n\troute(credentials);\n\tif (!pv_proxy_authorize("lab.sip")) {\n\t\tproxy_challenge("lab.sip", "auth", $var(algs));\n\t\texit;\n\t}\n\tconsume_credentials();\n\tswitch ($au) {\n\t\tcase "2001": $var(did) = "+442079460101"; break;\n\t\tcase "2002": $var(did) = "+442079460102"; break;\n\t\tcase "2003": $var(did) = "+442079460103"; break;\n\t\tdefault: $var(did) = "+442079460100"; break;\n\t}\n\tremove_hf("P-Asserted-Identity");\n\tappend_hf("P-Asserted-Identity: <sip:$var(did)@lab.sip;user=phone>\\r\\n");\n\t$rd = "carrier.example";\n\trecord_route();\n\tdo_accounting("db", "cdr|failed");   # answered calls (cdr) and refused or failed ones (failed)\n\t$acc_extra(caller) = $var(did);\n\t$acc_extra(callee) = $rU;\n\tt_on_reply("acc_times");\n\t$du = "sip:192.0.2.40:5060";   # the carrier\n\tt_relay();\n}\n'
# the answer and the BYE as each side saw them, to the microsecond (acc's own time column has whole seconds)
ACC_TIMES=$'\n# section 8: when this side saw the answer (the first 200 OK to the INVITE) and the BYE, to the microsecond, kept in\n# the CDR as answered_at and ended_at (Unix time, seconds.microseconds); acc\'s own time column has whole seconds\nonreply_route[acc_times] {\n\tif ($rs == 200 && is_method("INVITE") && $acc_extra(answered_at) == NULL) {\n\t\t$var(us) = "000000" + $Tsm;\n\t\t$acc_extra(answered_at) = "" + $Ts + "." + $(var(us){s.substr,-6,0});\n\t}\n}\n\nroute[acc_stop] {\n\t$var(us) = "000000" + $Tsm;\n\t$var(at) = "" + $Ts + "." + $(var(us){s.substr,-6,0});\n\tif (load_dialog_ctx($ci)) {\n\t\tacc_load_ctx_from_dlg();\n\t\tif ($acc_extra(ended_at) == NULL)\n\t\t\t$acc_extra(ended_at) = $var(at);\n\t\tacc_unload_ctx_from_dlg();\n\t\tunload_dialog_ctx();\n\t}\n}\n'
BYE_HOOK_OLD=$'\t\tif (loose_route()) {\n\t\t\tt_relay();\n'
BYE_HOOK_NEW=$'\t\tif (loose_route()) {\n\t\t\tif (is_method("BYE"))\n\t\t\t\troute(acc_stop);   # section 8: the BYE time in the CDR\n\t\t\tt_relay();\n'
trunk() {
  edit "$BYE_HOOK_OLD" "$BYE_HOOK_NEW"; printf '%s' "$ACC_TIMES" >> $CFG
  edit "$MODS" "$MODS$ACC_MODS"
  edit $'\tif ($fd == "lab.sip") {\n' "$TRUNK_ARM"$'\tif ($fd == "lab.sip") {\n'
  edit $'\n# the lab\'s users' "$OUT_ROUTE"$'\n# the lab\'s users'
}

# ---- the carrier: its own CDR for every call it sends to the far end ----
cacc() {  # cacc <create_dialog flags> <extra modparams> [script lines before the CDR starts]
  cedit "$BYE_HOOK_OLD" "$BYE_HOOK_NEW"; printf '%s' "$ACC_TIMES" >> $CCFG
  cedit "$MODS" "$MODS"$'\n# section 8: the carrier\'s own CDRs (acc with the dialog module), db_flatstore in /tmp/lab-cacc\nloadmodule "dialog.so"\n'"$2"$'loadmodule "db_flatstore.so"\nloadmodule "acc.so"\nmodparam("acc", "db_url", "flatstore:/tmp/lab-cacc")\nmodparam("acc", "extra_fields", "db: caller; callee; answered_at; ended_at")\n'
  cedit $'\t$du = "sip:192.0.2.50:5060";   # the far end\n' $'\t# section 8: the call is the carrier\'s from here on: a dialog and a CDR\n\tcreate_dialog('"${1:+\"$1\"}"$');\n\tdo_accounting("db", "cdr|failed");\n\t$acc_extra(caller) = $(ai{uri.user});\n\t$acc_extra(callee) = $rU;\n\tt_on_reply("acc_times");\n'"${3:-}"$'\t$du = "sip:192.0.2.50:5060";   # the far end\n'
}
row() { printf '%s\n' "$2" >> "$1"; }
CDB=/tmp/lab-carrier
rm -rf $CDB /tmp/lab-acc /tmp/lab-cacc; cp -r /usr/share/opensips/dbtext/opensips $CDB; mkdir -p /tmp/lab-acc /tmp/lab-cacc
row $CDB/address '1:1:192.0.2.10:32:0:any::acme SBC (IP trunk)'
row $CDB/address '2:2:192.0.2.50:32:0:any::the far end (interconnect)'

# ---- SIPp ----
calls() {  # calls <csv> <tag> <user> <ip[:port]> <scenario> <seconds> [sipp options]: a SIPp caller through our proxy
  # (a second caller on the same address takes another port: 5062, media from 6200)
  local csv=$1 tag=$2 u=$3 ip=${4%:*} port=5060 mp=6100 sc=$5 t=$6; [[ $4 == *:* ]] && { port=${4#*:}; mp=6200; }; shift 6
  local n; n=$(($(wc -l < "$csv") - 1))
  timeout "$t" sipp 192.0.2.10:5060 -sf $S/$sc -inf "$csv" -s "$u" -au "$u" -ap "lab-$u-pass" -i "$ip" -p $port \
    -mp $mp -m "$n" -timeout "${t}s" -nostdin -aa -trace_msg -message_file captures/$NAME.$tag.msg.log \
    -trace_stat -stf captures/$NAME.$tag.stat.csv "$@" > captures/$NAME.$tag.log 2>&1 || echo "$tag: sipp ended with an error"
}
far() {  # far <seconds>: the far end (every call that comes), in the carrier's namespace
  $C timeout "$1" sipp -sf $S/uas-bill.xml -s far -i 192.0.2.50 -p 5060 -mp 6000 -nostdin -aa -trace_msg \
    -message_file captures/$NAME.far.msg.log > captures/$NAME.far.log 2>&1 &
}
mi() {  # mi <proxy|carrier> <command> [args]: an MI command, its output appended to <name>.dlg.txt
  local who=$1 fifo=/run/opensips/opensips_fifo; shift
  [ "$who" = carrier ] && fifo=/run/opensips/carrier_fifo
  { echo "## $(stamp) $who: opensips-cli -x mi $*"
    opensips-cli -o fifo_file=$fifo -x mi "$@" 2>&1 | sed "s/\x1b\[[0-9;]*m//g"; echo; } >> captures/$NAME.dlg.txt
}
carrier_start() {  # carrier_start [faketime offset]: the carrier's OpenSIPS in its namespace (optionally on a wrong clock)
  local ft=(); [ -n "${1:-}" ] && ft=(faketime -f "$1")
  $C "${ft[@]}" /usr/sbin/opensips -F -f $CCFG -P /run/opensips/carrier.pid >> captures/$NAME.carrier.log 2>&1 & COSIPS=$!
  echo "$(stamp) carrier started${1:+ with its clock at $1 (libfaketime)}" >> captures/$NAME.faults.txt
  sleep 2
}
carrier_stop() { kill $COSIPS 2>/dev/null; sleep 1; pkill -f "opensips -F -f $CCFG" 2>/dev/null; sleep 1; }
carrier_idle() {  # carrier_idle <max seconds>: wait until the carrier holds no dialog (its hung calls ended)
  local t=0
  while [ $t -lt "$1" ] && opensips-cli -o fifo_file=/run/opensips/carrier_fifo -x mi dialog:list 2>/dev/null | grep -qi callid; do
    sleep 5; t=$((t + 5)); done
}
at_phase() {  # at_phase <hundredths>: wait until the clock's fraction of a second is <hundredths>/100
  local want=$1 now
  sleep 1
  while :; do now=$((10#$(date +%N) / 10000000)); [ "$now" -eq "$want" ] && break; sleep 0.003; done
}

# ======================================================================================================================
# 8.12: inbound calls stop after a few minutes (NAT binding gone; a separate set-up, nat.sh)
# ======================================================================================================================
if [ $CASE = nat ] || [ $CASE = natfix ]; then
  billnet down; ./nat.sh down; ./nat.sh up random > /dev/null
  RTR="ip netns exec router"; HM="ip netns exec home"; B1=4401; B2=4402
  # the router forgets an idle UDP binding after 60 s, whatever the binding saw (a request with a reply, or a stream)
  $RTR sysctl -q -w net.netfilter.nf_conntrack_udp_timeout=60 net.netfilter.nf_conntrack_udp_timeout_stream=60
  for f in nf_conntrack_udp_timeout nf_conntrack_udp_timeout_stream; do
    echo "router: net.netfilter.$f = $($RTR cat /proc/sys/net/netfilter/$f)"; done > captures/$NAME.timeouts.txt
  # our proxy fixes the signaling of a phone behind a NAT (nathelper, as in lesson 4.12); natfix adds keepalives:
  # an OPTIONS to every NATed binding every 20 s (natping_interval), which keeps the router's binding alive
  PING=0; [ $CASE = natfix ] && PING=20
  edit "$MODS" "$MODS"$'\n# lesson 8.12: NAT traversal on the server (nathelper); keepalives every natping_interval seconds (0 = none)\nloadmodule "nathelper.so"\nmodparam("nathelper", "received_avp", "$avp(received)")\nmodparam("registrar", "received_avp", "$avp(received)")\nmodparam("usrloc", "nat_bflag", "NAT")\nmodparam("nathelper", "natping_interval", '$PING$')\nmodparam("nathelper", "ping_nated_only", 1)\nmodparam("nathelper", "sipping_bflag", "SIPPING")\nmodparam("nathelper", "sipping_from", "sip:keepalive@lab.sip")\n'
  edit $'\tif (has_totag()) {\n' $'\t# lesson 8.12: answer where the request came from; a phone behind a NAT is reached at its public address and port\n\tforce_rport();\n\tif (nat_uac_test("private-contact,diff-ip-src-via,diff-port-src-via")) {\n\t\tif (is_method("REGISTER")) {\n\t\t\tfix_nated_register();\n\t\t\tsetbflag("NAT");\n\t\t\tsetbflag("SIPPING");\n\t\t} else {\n\t\t\tfix_nated_contact();\n\t\t}\n\t}\n\tt_on_reply("nat");\n\n\tif (has_totag()) {\n'
  printf '\n# lesson 8.12: a reply from a phone behind a NAT\nonreply_route[nat] {\n\tif (nat_uac_test("private-contact"))\n\t\tfix_nated_contact();\n}\n' >> $CFG
  diff $PLAIN $CFG > captures/$NAME.cfg.diff
  /usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
  $HM dnsmasq --keep-in-foreground --port=5353 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --no-hosts \
    --local=/lab.sip/ --host-record=lab.sip,192.0.2.10 > /dev/null 2>&1 &
  tcpdump -i any -U -s 0 -w captures/$NAME.pcap \
    '(udp or icmp) and (net 192.0.2.0/24 or net 198.51.100.0/24 or net 192.168.0.0/16)' 2>/dev/null & TCPD=$!
  $RTR tcpdump -i lan -U -s 0 -w captures/$NAME.home.pcap 'udp or icmp' 2>/dev/null & TCPH=$!
  sleep 1
  conf() {  # conf <dir> "key value": replace the key's line, commented or not, or add it
    local k=${2%% *} v=${2#* }
    if grep -q "^#\?$k[[:space:]]" "$1/config"; then sed -i "0,/^#\?$k[[:space:]].*/s||$k\t\t$v|" "$1/config"
    else printf '%s\t\t%s\n' "$k" "$v" >> "$1/config"; fi
  }
  # 2001 at home (registers with Expires 3600: baresip's regint), 2002 at the office on the internet side
  d=$(./baresip-phone.sh 2001 192.168.1.21 $B1 30000 ";audio_codecs=PCMU/8000/1;answermode=auto;answerdelay=1000")
  conf "$d" "dns_server 127.0.0.1:5353"
  $HM timeout 110 baresip -f "$d" -t 110 -s > captures/$NAME.2001.log 2>&1 &
  d=$(./baresip-phone.sh 2002 192.0.2.22 $B2 40000 ";audio_codecs=PCMU/8000/1")
  timeout 110 baresip -f "$d" -t 110 -s > captures/$NAME.2002.log 2>&1 &
  T0=$(date +%s)
  ctrack() { { echo "### t=$(( $(date +%s) - T0 )) s ($(stamp)): $1"; $RTR conntrack -L -p udp 2>&1; echo; } >> captures/$NAME.conntrack.txt; }
  sleep 3; ctrack "2001 registered (Expires 3600)"
  { echo "## $(stamp) opensips-cli -x mi usrloc:show_contact location 2001@lab.sip"
    opensips-cli -o fifo_file=/run/opensips/opensips_fifo -x mi usrloc:show_contact location 2001@lab.sip 2>&1; } > captures/$NAME.ul.txt
  # call 1, right after registering: 2002 calls 2001, who answers; 2002 hangs up after 4 s
  ./bctl.py $B2 dial sip:2001@lab.sip >> captures/$NAME.ctl.log 2>&1; sleep 6; ctrack "call 1 up"
  ./bctl.py $B2 hangup >> captures/$NAME.ctl.log 2>&1
  sleep 25; ctrack "35 s"; sleep 25; ctrack "60 s"; sleep 20; ctrack "80 s (more than 60 s after the last packet of call 1)"
  # call 2, after the binding's 60 s are over (natfix: the pings kept it)
  ./bctl.py $B2 dial sip:2001@lab.sip >> captures/$NAME.ctl.log 2>&1; sleep 8; ctrack "call 2, 8 s after the dial"
  ./bctl.py $B2 hangup >> captures/$NAME.ctl.log 2>&1; sleep 3
  for p in baresip dnsmasq; do pkill -x $p 2>/dev/null; done
  kill $TCPD $TCPH 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
  { echo "### the router's filter table at the end of the take (policy DROP counters: packets dropped)"; $RTR iptables -L -v -n
    echo; echo "### nat table"; $RTR iptables -t nat -L -v -n; } > captures/$NAME.router.txt 2>&1
  ./nat.sh down
  for P in $NAME $NAME.home; do
    tshark -r captures/$P.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst \
      -e udp.dstport -e _ws.col.Info 2>/dev/null > captures/$P.txt
    python3 pcap_messages.py captures/$P.pcap >/dev/null
  done
  for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
    sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
  done
  echo "=== internet side"; cat captures/$NAME.txt; echo "=== home side"; cat captures/$NAME.home.txt
  exit 0
fi

# ======================================================================================================================
# the billing cases
# ======================================================================================================================
trunk
OFFSET=   # a wrong clock for the carrier (duration)
case $CASE in
  # 8.8: a burst of 30 calls (2 per second, 8 s each) while the network between us and the carrier stops carrying
  # anything toward us for 7 s (a one-way outage). The far end answers every call; the carrier sees every answer;
  # our proxy sees none of the replies of the calls set up in the window: our tm gives up (408 after fr_timeout 5 s)
  # and our CDR says failed, the carrier's says answered (the far end hangs up with its own BYE when no ACK comes).
  count)    cacc "" "" ;;
  # 8.9: one call per cause. 1) answer time: the first two copies of the far end's 200 OK are lost on the way to us
  # (the far end resends it at 0.5 s and 1.5 s): the carrier's clock starts 1.5 s before ours (a 59 s call); 2) session
  # disconnect delay: the first two copies of our BYE are lost on the way to the carrier (our proxy resends it):
  # the carrier stops its clock 1.5 s after ours; 3) clock offset: the carrier's OpenSIPS runs on a clock 1.5 s ahead
  # (libfaketime, simulated); 4) rounding: three short calls (0.2, 1.0, 1.8 s) on that clock, placed at chosen
  # fractions of a second, as the deck's slide 189.
  duration) cacc "" "" ;;
  # 8.10: the carrier keeps a dialog at most 120 s here (dialog default_timeout; the production default is 43200 s,
  # 12 hours) and ends it with BYEs both ways when it expires (bye-on-timeout); it allows 2 calls at once per calling
  # number (a dialog profile; the third gets 503 "Call Limit Reached": a lab choice of reply); acc counts early media.
  hungbill) cacc "bye-on-timeout" $'modparam("dialog", "default_timeout", 120)\nmodparam("dialog", "profiles_with_value", "calls")\n' \
              $'\t# lesson 8.10: at most 2 calls at once per calling number (dialog profile "calls"); a lab choice of reply\n\tget_profile_size("calls", $(ai{uri.user}), $var(n));\n\tif ($var(n) >= 2) {\n\t\txlog("L_NOTICE", "carrier: $(ai{uri.user}) already has $var(n) calls up: 503\\n");\n\t\tt_newtran();\n\t\tsend_reply(503, "Call Limit Reached");\n\t\texit;\n\t}\n\tset_dlg_profile("calls", $(ai{uri.user}));\n'
            editf $CCFG 'modparam("acc", "db_url", "flatstore:/tmp/lab-cacc")' $'modparam("acc", "db_url", "flatstore:/tmp/lab-cacc")\nmodparam("acc", "early_media", 1)   # lesson 8.10: a 183 with SDP is accounted too' ;;
  # 8.11: "the carrier bills 3% more minutes than our CDRs": a scaled-down day of 80 calls (10-60 s each, seeded), with
  # the network's faults of a bad day: every 12th SIP packet each way lost, and two 6 s one-way outages toward the
  # carrier (at 55 s and 100 s). The carrier keeps a dialog at most 100 s (scaled down from 12 h) and ends it with BYEs (bye-on-timeout).
  # ticketfix = the same day with the fix: the carrier pings the caller's side of every call with in-dialog OPTIONS
  # every 10 s (create_dialog options-ping-caller): a call whose caller is gone ends at the first unanswered ping.
  ticket)   cacc "bye-on-timeout" $'modparam("dialog", "default_timeout", 100)\n' ;;
  ticketfix|ticketfix5) cacc "bye-on-timeout,options-ping-caller" $'modparam("dialog", "default_timeout", 100)\nmodparam("dialog", "options_ping_interval", 10)\n'
            # a ping is a non-INVITE transaction: with the lab's fr_timeout of 5 s, a 6 s outage makes every ping of a
            # live call fail and the carrier hangs those calls up (kept as ticketfix5); ticketfix gives the carrier the
            # RFC's 32 s (Timer F, 64*T1), so a ping outlives a short outage
            [ $CASE = ticketfix ] && cedit 'modparam("tm", "fr_timeout", 5)' 'modparam("tm", "fr_timeout", 32)   # lesson 8.11: Timer F as RFC 3261 17.1.2.2 (64*T1)' ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac
diff $PLAIN $CFG > captures/$NAME.cfg.diff
diff opensips/carrier.cfg $CCFG > captures/$NAME.carrier.cfg.diff

billnet up
tcpdump -i any -U -s 0 -w captures/$NAME.pcap '(udp or icmp) and net 192.0.2.0/24' 2>/dev/null & TCPD=$!
$C tcpdump -i any -U -s 0 -w captures/$NAME.carrier.pcap 'udp or icmp' 2>/dev/null & TCPC=$!
sleep 1
/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!
COSIPS=
case $CASE in duration) ;; *) carrier_start ;; esac
sleep 1
csv() {  # csv <file> <number;ms>...: a SIPp injection file
  { echo SEQUENTIAL; printf '%s\n' "${@:2}"; } > "$1"
}

case $CASE in
  count)
    csv captures/$NAME.calls.csv $(for i in $(seq 10 39); do echo "+4416149601$i;8000"; done)
    far 90
    calls captures/$NAME.calls.csv 2001 2001 192.0.2.21 bill-uac.xml 70 -r 2 -l 30 &
    UAC=$!
    sleep 5; lose to_us "outage toward us"; sleep 7; unlose "outage toward us"
    wait $UAC; mi proxy dialog:list; mi carrier dialog:list
    carrier_idle 60; sleep 6; mi carrier dialog:list ;;
  duration)
    carrier_start
    far 200
    # 1) answer time, a 59 s call: the far end's first two 200 OKs are lost toward us
    csv captures/$NAME.answer.csv "+441614960142;59000"
    lose to_us "first two 200 OK" -m string --algo bm --string "SIP/2.0 200 OK" -m string --algo bm --string "INVITE" \
      -m limit --limit 1/hour --limit-burst 2
    calls captures/$NAME.answer.csv answer 2001 192.0.2.21 bill-uac.xml 70
    unlose "first two 200 OK"
    # 2) session disconnect delay, a 6 s call: our first two BYEs are lost toward the carrier
    csv captures/$NAME.sdd.csv "+441614960143;6000"
    lose to_carrier "first two BYE" -m string --algo bm --string "BYE sip:" -m limit --limit 1/hour --limit-burst 2
    calls captures/$NAME.sdd.csv sdd 2001 192.0.2.21 bill-uac.xml 20
    unlose "first two BYE"
    # 3) and 4): the carrier on a clock 1.5 s ahead; a 6 s call, then the three short calls, each started at a chosen
    # fraction of a second so that it is answered (about 0.13 s later on this box) at about .40, .10 and .30 s on our
    # clock (.90, .60 and .80 on the carrier's), the cases of slide 189
    carrier_stop; OFFSET="+1.5s"; carrier_start "$OFFSET"
    csv captures/$NAME.offset.csv "+441614960144;6000"
    calls captures/$NAME.offset.csv offset 2001 192.0.2.21 bill-uac.xml 20
    for c in "short200 +441614960100;200 27" "short1800 +441614960100;1800 97" "short1000 +441614960100;1000 17"; do
      set -- $c
      csv captures/$NAME.$1.csv "$2"
      at_phase "$3"; echo "$(stamp) $1: call starts (wanted at 0.$(printf %02d $3) s)" >> captures/$NAME.faults.txt
      calls captures/$NAME.$1.csv "$1" 2001 192.0.2.21 bill-uac.xml 15
    done
    mi proxy dialog:list; mi carrier dialog:list ;;
  hungbill)
    far 170
    # a hung call: 2001's BYE never reaches the carrier (every copy lost toward the carrier for 8 s)
    csv captures/$NAME.hung.csv "+441614960142;5000"
    calls captures/$NAME.hung.csv hung 2001 192.0.2.21 bill-uac.xml 20 &
    UAC=$!; sleep 4; lose to_carrier "every BYE" -m string --algo bm --string "BYE sip:"; wait $UAC
    sleep 2; unlose "every BYE"
    mi proxy dialog:list; mi carrier dialog:list
    # the next two calls of the same account: the carrier still counts the hung call
    csv captures/$NAME.second.csv "+441614960143;20000"
    calls captures/$NAME.second.csv second 2001 192.0.2.21 bill-uac.xml 30 &
    UAC=$!; sleep 3; mi carrier dialog:profile_get_size calls +442079460101
    csv captures/$NAME.third.csv "+441614960144;3000"
    calls captures/$NAME.third.csv third 2001 192.0.2.21:5062 bill-uac.xml 15
    # the dialer (account 2003): 12 short calls, at most 2 at once (its limit at the carrier); three reach the
    # announcement (early media) and are cancelled after 6 s, the others are answered and last 2-4 s
    csv captures/$NAME.dialer.csv "+441614960150;3000" "+441614960999;3000" "+441614960151;2000" "+441614960152;4000" \
      "+441614960999;3000" "+441614960153;2000" "+441614960154;3000" "+441614960155;2000" "+441614960999;3000" \
      "+441614960156;4000" "+441614960157;2000" "+441614960158;3000"
    calls captures/$NAME.dialer.csv dialer 2003 192.0.2.23 dialer-uac.xml 60 -r 2 -l 2
    wait $UAC
    # the hung call's dialog until the carrier's timeout (120 s after its answer)
    carrier_idle 300
    sleep 3; mi carrier dialog:list ;;
  ticket|ticketfix|ticketfix5)
    # the day: 80 calls of 10-60 s, seeded (the same day in both takes), one per second, numbers +44 161 496 0110-0189
    python3 - captures/$NAME.calls.csv <<'EOF'
import random, sys
rng = random.Random(8011)
with open(sys.argv[1], "w") as f:
    f.write("SEQUENTIAL\n")
    for i in range(80):
        f.write(f"+4416149601{10 + i};{rng.randint(10, 60) * 1000 + rng.randint(0, 999)}\n")
EOF
    lose to_us "every 12th SIP packet toward us" -m statistic --mode nth --every 12 --packet 0
    lose to_carrier "every 12th SIP packet toward the carrier" -m statistic --mode nth --every 12 --packet 0
    far 240
    calls captures/$NAME.calls.csv day 2001 192.0.2.21 bill-uac.xml 200 -r 1 -l 80 &
    UAC=$!
    sleep 55; lose to_carrier "outage toward the carrier"; sleep 6; unlose "outage toward the carrier"
    sleep 39; lose to_carrier "second outage toward the carrier"; sleep 6; unlose "second outage toward the carrier"
    wait $UAC
    unlose "every 12th SIP packet toward us"; unlose "every 12th SIP packet toward the carrier"
    mi proxy dialog:list; mi carrier dialog:list
    carrier_idle 300
    sleep 3; mi carrier dialog:list ;;
esac

sleep 1; pkill -x sipp 2>/dev/null
kill $TCPD $TCPC 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; carrier_stop
{ echo "### transit FORWARD at the end (rules still present are listed with their counters)"; $X iptables -L FORWARD -v -n -x; } \
  >> captures/$NAME.faults.txt
billnet down
rm -rf $CDB

# the CDRs: the raw lines of each side, then both with a header
sort -t'|' -k7,7n /tmp/lab-acc/acc_*.log 2>/dev/null > captures/$NAME.ours.cdr
sort -t'|' -k7,7n /tmp/lab-cacc/acc_*.log 2>/dev/null > captures/$NAME.carrier.cdr
{ echo "# acc CDRs (db_flatstore, joined and sorted by time). Columns:"
  echo "# method|from_tag|to_tag|callid|sip_code|sip_reason|time|caller|callee|answered_at|ended_at|setuptime|created|duration|ms_duration"
  echo "# time = when the call was answered (or refused), created = when its INVITE arrived (Unix seconds); answered_at and"
  echo "# ended_at = when this side saw the 200 OK and the BYE (Unix seconds.microseconds, set by the script; empty when the"
  echo "# side never saw them, e.g. a BYE the carrier made itself); setuptime and duration in seconds (duration counts every"
  echo "# started second), ms_duration in milliseconds. Refused or failed calls: setuptime and durations 0."
  [ -n "$OFFSET" ] && echo "# The carrier's OpenSIPS ran on a clock $OFFSET ahead (libfaketime) for the calls after the restart."
  echo; echo "## our proxy (192.0.2.10)"; cat captures/$NAME.ours.cdr
  echo; echo "## the carrier (192.0.2.40)"; cat captures/$NAME.carrier.cdr; } > captures/$NAME.cdr.txt
rm -rf /tmp/lab-acc /tmp/lab-cacc
ALL=; case $CASE in duration|hungbill) ALL=" --all" ;; esac
{ echo "lab@sip-lab:~/lab\$ python3 cdr_compare.py captures/$NAME.ours.cdr captures/$NAME.carrier.cdr$ALL"
  python3 cdr_compare.py captures/$NAME.ours.cdr captures/$NAME.carrier.cdr$ALL; } > captures/$NAME.compare.txt 2>&1
for P in $NAME $NAME.carrier; do
  tshark -r captures/$P.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e frame.time_epoch -e ip.src \
    -e ip.dst -e sip.Call-ID -e _ws.col.Info 2>/dev/null |
    awk -F'\t' -v OFS='\t' '{ $3 = strftime("%H:%M:%S", int($3)) sprintf(".%03d", ($3 - int($3)) * 1000); print }' \
    > captures/$P.txt
  python3 pcap_messages.py captures/$P.pcap >/dev/null
done
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
[ -s captures/$NAME.rtp.txt ] && grep -q '[0-9]' captures/$NAME.rtp.txt || rm -f captures/$NAME.rtp.txt
# mask every eth0/eth1 IPv4 (the droplet's public and private addresses) in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.*diff captures/$NAME.*cdr 2>/dev/null
done
cat captures/$NAME.compare.txt
