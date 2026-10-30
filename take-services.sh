#!/bin/bash
# sip-lab takes for section 5 part B (forwarding, history, hunt groups, conferences, park and pickup, busy lamps and the
# voicemail light, third-party call control, MESSAGE and INFO): RFC 5359 sections 2.7-2.18 and the event packages.
# Same plumbing as take-errors.sh: baresip phones where a real phone can play the role (baresip-phone.sh, driven by
# bctl.py), SIPp where baresip 1.1.0 cannot (it ignores Replaces, refuses Join with 420, answers an out-of-dialog REFER
# with 501, has no dialog event package and no Info Packages), OpenSIPS as the proxy. Most cases run lab.cfg with
# changes (forwarding rules, hunt groups, presence server, message store), saved as captures/<name>.cfg.diff.
#   sudo ./take-services.sh <case> <name>
# Addresses: proxy 192.0.2.10, phones 2001-2003 = 192.0.2.21-.23 (baresip or SIPp), 2004/2005 = 192.0.2.24/.25 (SIPp),
# 192.0.2.30 = an application server (voicemail, park server, 3PCC controller, "Bob's PC"), trusted by the proxy by its
# address (no digest). Bob the conference host is a SIPp phone at 192.0.2.22.
# Cases (lesson): fwd302 fwdcfu fwdbusy fwdnoans (5.9), histdiv histhi (5.10), hunt ring (5.11), confadd confjoin joinbaresip
# joinbaresip (5.12), park pickup (5.13), blf mwi (5.14), 3pcc clickrefer redial (5.15), message infopkg infophone infodtmf (5.16),
# ticket ticketfix (5.17). Each writes captures/<name>.pcap (SIP + RTP + ICMP on lo), .txt (SIP summary),
# .messages.txt (pcap_messages.py), .rtp.txt, .media.txt, the logs of every element (SIPp: <tag>.log and the messages
# it sent and got, <tag>.msg.log) and .cfg.diff. Leaves nothing running (extra addresses removed, the presence and
# message store database in /tmp/lab-presence deleted).
# SIPp roles that hold several dialogs give the extra ones a Call-ID "<name>///<the call's Call-ID>": SIPp matches a
# Call-ID on what follows "///". A new dialog that comes in to a SIPp caller is played by an out-of-call scenario
# (-oocsf); the two share global variables.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
mkdir -p /run/opensips
S=scenarios
B1=4401; B2=4402; B3=4403
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
addr() { ip addr add "$1/32" dev lab0 2>/dev/null; ADDRS+=("$1"); }
LOOKUP=$'\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n'
RELAY=$'\tt_relay();\n}\n\n# the lab\'s users'
AUTH=$'\tif ($fd == "lab.sip") {\n'
users() {  # users <n>...: passwords for extra lab users (2004, 2005)
  local u lines=""
  for u in "$@"; do lines+=$'\t\tcase "'$u$'": $avp(passspec) = "lab-'$u$'-pass"; break;\n'; done
  edit $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n' \
       $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n'"$lines"
}
trusted() {  # the application server 192.0.2.30 (and the proxy itself) skip proxy authentication
  edit "$AUTH" $'\t# the application server (192.0.2.30) and this proxy (its own PUBLISHes) are trusted by address\n\tif ($fd == "lab.sip" && $si != "192.0.2.30" && $si != "192.0.2.10") {\n'
}
presence() {  # the proxy is also the presence server: dialog event (from its own dialogs) and message-summary
  edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# presence server (section 5): the dialog event package, published by this proxy from the calls it routes\n# (pua_dialoginfo), and message-summary (the voicemail light), published by the voicemail server\nloadmodule "db_text.so"\nloadmodule "dialog.so"\nloadmodule "presence.so"\nmodparam("presence", "db_url", "text:///tmp/lab-presence")\nloadmodule "presence_dialoginfo.so"\nloadmodule "presence_mwi.so"\nloadmodule "pua.so"\nmodparam("pua", "db_url", "text:///tmp/lab-presence")\nloadmodule "pua_dialoginfo.so"\nmodparam("pua_dialoginfo", "presence_server", "sip:presence@192.0.2.10:5060")\nmodparam("pua_dialoginfo", "publish_on_trying", 1)   # the caller\'s "trying" too\n'
  edit $'\t\t} else if (is_method("ACK")) {\n' $'\t\t} else if (is_method("SUBSCRIBE") && $rd == "192.0.2.10") {\n\t\t\troute(presence);   # a refresh or an unsubscribe: in-dialog, sent to the presence server\n\t\t} else if (is_method("ACK")) {\n'
  edit $'\trecord_route();\n' $'\tif (is_method("PUBLISH|SUBSCRIBE")) {\n\t\troute(presence);\n\t\texit;\n\t}\n\tif (is_method("INVITE")) {\n\t\tcreate_dialog();\n\t\tdialoginfo_set();   # publish this call\'s states for the caller (From) and the callee (Request-URI)\n\t}\n\n\trecord_route();\n'
  edit "$RELAY" $'\tt_relay();\n}\n\n# the presence server: SUBSCRIBE (dialog, message-summary) and PUBLISH\nroute[presence] {\n\tif (!t_newtran()) {\n\t\tsl_reply_error();\n\t\texit;\n\t}\n\tif (is_method("PUBLISH"))\n\t\thandle_publish();\n\telse\n\t\thandle_subscribe();\n\texit;\n}\n\n# the lab\'s users'
  trusted
  rm -rf /tmp/lab-presence; cp -r /usr/share/opensips/dbtext/opensips /tmp/lab-presence
}

before_lookup() {  # before_lookup <script lines>: insert lines just before the location lookup of initial requests
  edit "$LOOKUP" "$1$LOOKUP"
}
after_lookup() {  # after_lookup <script lines>: insert lines between the location lookup and t_relay()
  edit "$LOOKUP$RELAY" "$LOOKUP$1$RELAY"
}
routes() {  # routes <route blocks>: add failure/branch routes after the main route
  edit $'\n# the lab\'s users' "$1"$'\n# the lab\'s users'
}
FWD_FAILURE=$'\n# lesson 5.9: 2002 forwards to 2003 when its phone is busy (486) or nobody answers before the timer (408)\nfailure_route[forward] {\n\tif (t_was_cancelled())\n\t\texit;\n\tif (t_check_status("486|408")) {\n\t\t$ru = "sip:2003@lab.sip";\n\t\tif (!lookup("location")) {\n\t\t\tt_reply(404, "Not Found");\n\t\t\texit;\n\t\t}\n\t\tt_relay();\n\t}\n}\n'
HI_ROUTES=$'\n# lesson 5.10: 2002 busy (486): History-Info for the target that failed, with its Reason, and for the forwarding\n# target, a different user (mp = mapped from entry 1); then the call goes to 2003\nfailure_route[forward] {\n\tif (t_was_cancelled())\n\t\texit;\n\tif (t_check_status("486")) {\n\t\tappend_hf("History-Info: <$avp(hi_target)?Reason=SIP%3Bcause%3D486%3Btext%3D%22Busy%20Here%22>;index=1.1;rc=1\\r\\n");\n\t\tappend_hf("History-Info: <sip:2003@lab.sip>;index=1.2;mp=1\\r\\n");\n\t\t$ru = "sip:2003@lab.sip";\n\t\tif (!lookup("location")) {\n\t\t\tt_reply(404, "Not Found");\n\t\t\texit;\n\t\t}\n\t\t$avp(hi_index) = "1.2.1";\n\t\t$avp(hi_rc) = "1.2";\n\t\tt_on_branch("history");\n\t\tt_relay();\n\t}\n}\n\n# lesson 5.10: each target the proxy sends the INVITE to gets its History-Info entry (rc: retargeted by the location\n# service, from the entry with index hi_rc)\nbranch_route[history] {\n\tappend_hf("History-Info: <$ru>;index=$avp(hi_index);rc=$avp(hi_rc)\\r\\n");\n}\n'
HUNT_GROUPS=$'\t# lesson 5.11: hunt group 2100 (find-me): 2002, 2004, 2005, 2003 one after another, 6 s each\n\tif ($rU == "2100") {\n\t\t$avp(hunt_step) = 0;\n\t\t$ru = "sip:2002@lab.sip";\n\t\troute(hunt);\n\t\texit;\n\t}\n\t# lesson 5.11: ring group 2200: 2002, 2004 and 2003 ring at the same time (three branches); the first 200 wins\n\tif ($rU == "2200") {\n\t\t$ru = "sip:2002@lab.sip";\n\t\tlookup("location");\n\t\t$branch = $ru;   # keep this contact as a branch\n\t\t$ru = "sip:2004@lab.sip";\n\t\tlookup("location");\n\t\t$branch = $ru;   # keep this contact as a branch\n\t\t$ru = "sip:2003@lab.sip";\n\t\tlookup("location");\n\t\tt_relay();\n\t\texit;\n\t}\n'
HUNT_ROUTES=$'\n# lesson 5.11: one member of the hunt group, with a 6 s no-answer timer\nroute[hunt] {\n\tlookup("location");\n\t$T_fr_inv_timeout = 6;\n\tt_on_failure("hunt");\n\tt_relay();\n}\n\n# lesson 5.11: that member did not answer (a final error or the timer): try the next one\nfailure_route[hunt] {\n\tif (t_was_cancelled())\n\t\texit;\n\t$avp(hunt_step) = $avp(hunt_step) + 1;\n\tswitch ($avp(hunt_step)) {\n\t\tcase 1: $ru = "sip:2004@lab.sip"; break;\n\t\tcase 2: $ru = "sip:2005@lab.sip"; break;\n\t\tcase 3: $ru = "sip:2003@lab.sip"; break;\n\t\tdefault: exit;   # the last member failed too: its reply goes back to the caller\n\t}\n\troute(hunt);\n}\n'
FWD_ARM=$'\t# lesson 5.9: call forwarding on busy and on no answer for 2002 (to 2003), with an 8 s no-answer timer\n\tif ($rU == "2002") {\n\t\t$T_fr_inv_timeout = 8;\n\t\tt_on_failure("forward");\n\t}\n'

case $CASE in
  blf|mwi|pickup|redial|ticket|ticketfix) presence ;;
  # the 3PCC controller is the application server at 192.0.2.30
  3pcc)    trusted ;;
  # RFC 5359 2.7: the proxy itself forwards every call for 2002 to 2003 (the target is just another URI to it)
  fwdcfu)  before_lookup $'\t# lesson 5.9: 2002 forwards every call to 2003 (call forwarding unconditional, kept in the proxy)\n\tif ($rU == "2002")\n\t\t$rU = "2003";\n' ;;
  # RFC 5359 2.8 and 2.9: forwarding on busy and on no answer, done by the proxy in a failure route
  fwdbusy|fwdnoans) before_lookup "$FWD_ARM"; routes "$FWD_FAILURE" ;;
  # RFC 5359 2.12 and RFC 3261 16.6-16.7: a hunt group (serial) and a ring group (parallel) kept in the proxy script
  hunt|ring) users 2004 2005; before_lookup "$HUNT_GROUPS"; routes "$HUNT_ROUTES" ;;
  # RFC 5359 2.15: the park server (sip:park@lab.sip) is the application server at 192.0.2.30
  park)    trusted
           before_lookup $'\t# lesson 5.13: the park server is the application server\n\tif ($rU == "park") {\n\t\t$du = "sip:192.0.2.30:5060";\n\t\tt_relay();\n\t\texit;\n\t}\n' ;;
  # RFC 3428 MESSAGE: delivered when the user is registered; otherwise stored by the proxy (msilo: 202 Accepted) and
  # sent when the user registers
  message) trusted
           edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# lesson 5.16: a message store for users who are not registered (msilo)\nloadmodule "db_text.so"\nloadmodule "msilo.so"\nmodparam("msilo", "db_url", "text:///tmp/lab-presence")\n'
           edit $'\t\tif (!save("location"))\n\t\t\tsend_reply(500, "Server Internal Error");\n\t\texit;\n' $'\t\tif (!save("location"))\n\t\t\tsend_reply(500, "Server Internal Error");\n\t\telse\n\t\t\tm_dump();   # lesson 5.16: deliver the messages kept for this user\n\t\texit;\n'
           before_lookup $'\t# lesson 5.16: a MESSAGE for a user who is not registered is kept (202 Accepted) and sent when they register\n\tif (is_method("MESSAGE")) {\n\t\tif (!lookup("location")) {\n\t\t\tif (!m_store()) {\n\t\t\t\tsend_reply(500, "Server Internal Error");\n\t\t\t\texit;\n\t\t\t}\n\t\t\tsend_reply(202, "Accepted");\n\t\t\texit;\n\t\t}\n\t\tt_relay();\n\t\texit;\n\t}\n'
           rm -rf /tmp/lab-presence; cp -r /usr/share/opensips/dbtext/opensips /tmp/lab-presence ;;
  # the busy forwarding of fwdbusy, and the proxy writes Diversion (RFC 5806, diversion module) on the forwarded INVITE
  histdiv) before_lookup "$FWD_ARM"; routes "$FWD_FAILURE"
           edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\nloadmodule "diversion.so"\n'
           edit $'\tif (t_check_status("486|408")) {\n' $'\tif (t_check_status("486|408")) {\n\t\t# lesson 5.10: say who forwarded the call and why (RFC 5806)\n\t\tif (t_check_status("486"))\n\t\t\tadd_diversion("user-busy", "sip:2002@lab.sip");\n\t\telse\n\t\t\tadd_diversion("no-answer", "sip:2002@lab.sip");\n' ;;
  # the same busy forwarding with History-Info (RFC 7044): the caller writes index 1; the proxy writes one entry per
  # target it tries (branch route: the registered contact, rc = retargeted by the location service), and on the 486 the
  # failed entry with its Reason and the forwarding target (mp = mapped to another user). OpenSIPS 4.0 has no
  # History-Info module: these are script lines (append_hf).
  histhi)  before_lookup "$FWD_ARM"
           after_lookup $'\t# lesson 5.10: History-Info for the first target (the contact found by the location service)\n\t$avp(hi_target) = $ru;\n\t$avp(hi_index) = "1.1";\n\t$avp(hi_rc) = "1";\n\tt_on_branch("history");\n'
           routes "$HI_ROUTES" ;;
esac
cmp -s $PLAIN $CFG || diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] ["key value" config line]...: PCMU only
  local u=$1 ip=$2 c=$3 r=$4 t=$5 p=${6:-} d kv k v; shift 5; [ $# -gt 0 ] && shift
  d=$(./baresip-phone.sh "$u" "$ip" "$c" "$r" ";audio_codecs=PCMU/8000/1$p")
  for m in ${MODS:-}; do sed -i "s|^#\(module_app[[:space:]]*$m.so\)|\1|" "$d/config"; done   # MODS="mwi": extra modules
  for kv in "$@"; do  # replace the key's line, commented or not (baresip reads the first one), or add it
    k=${kv%% *} v=${kv#* }
    if grep -q "^#\?$k[[:space:]]" "$d/config"; then sed -i "0,/^#\?$k[[:space:]].*/s||$k\t\t$v|" "$d/config"
    else printf '%s\t\t%s\n' "$k" "$v" >> "$d/config"; fi
  done
  timeout "$t" baresip -f "$d" -t "$t" -s > captures/$NAME.$u.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip> [port]
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p "${3:-5060}" -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
uas() {  # uas <scenario> <seconds> <log tag> <user> <ip> <rtp port> [sipp options]: a SIPp callee (one call)
  local sc=$1 t=$2 tag=$3 u=$4 ip=$5 mp=$6; shift 6
  timeout "$t" sipp -sf $S/$sc -s "$u" -au "$u" -ap "lab-$u-pass" -i "$ip" -p 5060 -mp "$mp" -m 1 -timeout "${t}s" \
    -nostdin -trace_msg -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 &
}
uac() {  # uac <scenario> <seconds> <log tag> <user> <ip[:port]> <rtp port> [sipp options]: a SIPp caller through the proxy
  local sc=$1 t=$2 tag=$3 u=$4 ip=${5%:*} port=5060 mp=$6; [[ $5 == *:* ]] && port=${5#*:}; shift 6
  timeout "$t" sipp 192.0.2.10:5060 -sf $S/$sc -s "$u" -au "$u" -ap "lab-$u-pass" -i "$ip" -p $port -mp "$mp" -m 1 \
    -timeout "${t}s" -nostdin -trace_msg -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 \
    || echo "$tag: sipp ended with an error"
}
BGP=()
bg() { "$@" & BGP+=($!); }   # run a SIPp caller in the background
bgwait() { [ ${#BGP[@]} -gt 0 ] && wait "${BGP[@]}"; }
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
dial() { ctl 0 $1 dial "$2"; }

case $CASE in
  # busy lamp: SIPp 2003 (192.0.2.23) watches 2002 (Event: dialog, Expires 60, refreshes after 15 quiet seconds, then
  # unsubscribes); baresip 2001 calls baresip 2002, which answers after 3 s; 2001 hangs up 8 s later. The proxy
  # publishes each state of the call (pua_dialoginfo) and its presence server notifies the watcher.
  # busy lamps: SIPp 2003 (192.0.2.23) watches 2002 (port 5060) and 2001 (port 5062): Event: dialog, Expires 60,
  # a refresh after 15 quiet seconds, then an unsubscribe; baresip 2001 calls baresip 2002, which answers after 3 s;
  # 2001 hangs up 8 s later. The proxy publishes each state of the call for both users (pua_dialoginfo, with the
  # caller's "trying") and its presence server notifies the watchers.
  blf)      W="-set event dialog -set accept application/dialog-info+xml -set expires 60 -set refresh 1 -set stopafter 2"
            bg uac sub-watch.xml 70 watch2002 2003 192.0.2.23 50000 -auth_uri 2002@lab.sip -set target 2002 $W \
              -aa
            bg uac sub-watch.xml 70 watch2001 2003 192.0.2.23:5062 50010 -auth_uri 2001@lab.sip -set target 2001 $W \
              -aa
            phone 2002 192.0.2.22 $B2 40000 30 ";answermode=auto;answerdelay=3000"; phone 2001 192.0.2.21 $B1 30000 30
            sleep 4; dial $B1 sip:2002@lab.sip; ctl 11 $B1 hangup; sleep 40; bgwait ;;
  # the voicemail light: baresip 2001 loads its mwi module, which subscribes to message-summary for its own AOR; the
  # voicemail server (SIPp at 192.0.2.30) publishes 2 new messages, then 8 s later none; the proxy's presence server
  # notifies the phone each time
  mwi)      addr 192.0.2.30
            MODS=mwi phone 2001 192.0.2.21 $B1 30000 20; sleep 4
            uac pub-mwi.xml 14 vm voicemail 192.0.2.30 0 -set target 2001 -set later 8000; sleep 4 ;;
  # RFC 5359 2.7 with a redirect: 2002 (SIPp at 192.0.2.22) answers 302 Moved Temporarily, Contact sip:2003@lab.sip;
  # baresip 2001 follows it with a new INVITE to 2003 (baresip, answers after 1.5 s); 2001 hangs up 6 s later
  fwd302)   sipp_reg 2002 192.0.2.22
            uas uas-302.xml 12 uas 2002 192.0.2.22 40000 \
              -set contact sip:2003@lab.sip
            phone 2003 192.0.2.23 $B3 50000 16 ";answermode=auto;answerdelay=1500"; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial $B1 sip:2002@lab.sip; ctl 8 $B1 hangup; sleep 2 ;;
  # RFC 5359 2.7 as drawn: the proxy rewrites the Request-URI 2002 -> 2003 (2002 is not even registered)
  fwdcfu)   phone 2003 192.0.2.23 $B3 50000 16 ";answermode=auto;answerdelay=1500"; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial $B1 sip:2002@lab.sip; ctl 8 $B1 hangup; sleep 2 ;;
  # RFC 5359 2.8: 2002 (SIPp) answers 486 Busy Here at once; the proxy's failure route sends the call to 2003
  fwdbusy)  sipp_reg 2002 192.0.2.22; uas uas-486.xml 12 uas 2002 192.0.2.22 40000
            phone 2003 192.0.2.23 $B3 50000 16 ";answermode=auto;answerdelay=1500"; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial $B1 sip:2002@lab.sip; ctl 8 $B1 hangup; sleep 2 ;;
  # RFC 5359 2.9: baresip 2002 rings and nobody answers; at 8 s the proxy CANCELs it (487) and calls 2003
  fwdnoans) phone 2002 192.0.2.22 $B2 40000 24; phone 2003 192.0.2.23 $B3 50000 24 ";answermode=auto;answerdelay=1500"
            phone 2001 192.0.2.21 $B1 30000 24; sleep 3; dial $B1 sip:2002@lab.sip; ctl 16 $B1 hangup; sleep 2 ;;
  # RFC 5359 2.12 find-me: hunt group 2100 tries 2002 (baresip, rings: CANCEL at 6 s), 2004 (SIPp, 480), 2005 (SIPp,
  # 486) and 2003 (baresip, answers after 2 s), one after another; 2003 hangs up 6 s after answering
  hunt)     addr 192.0.2.24; addr 192.0.2.25; sipp_reg 2004 192.0.2.24; sipp_reg 2005 192.0.2.25
            uas uas-480.xml 30 uas2004 2004 192.0.2.24 41000; uas uas-486.xml 30 uas2005 2005 192.0.2.25 42000
            phone 2002 192.0.2.22 $B2 40000 30; phone 2003 192.0.2.23 $B3 50000 30 ";answermode=auto;answerdelay=2000"
            phone 2001 192.0.2.21 $B1 30000 30; sleep 3; dial $B1 sip:2100@lab.sip; ctl 14 $B3 hangup; sleep 3 ;;
  # ring group 2200: 2002 (baresip) and 2004 (SIPp) ring with 2003 (baresip, answers after 3 s); the proxy CANCELs the
  # other two; 2001 hangs up 5 s after the answer
  ring)     addr 192.0.2.24; sipp_reg 2004 192.0.2.24; uas uas-ring.xml 20 uas2004 2004 192.0.2.24 41000
            phone 2002 192.0.2.22 $B2 40000 20; phone 2003 192.0.2.23 $B3 50000 20 ";answermode=auto;answerdelay=3000"
            phone 2001 192.0.2.21 $B1 30000 20; sleep 3; dial $B1 sip:2200@lab.sip; ctl 8 $B1 hangup; sleep 3 ;;
  # RFC 5359 2.10: baresip 2001 (Alice) calls 2002 (Bob, SIPp at 192.0.2.22, a phone that mixes); Bob re-INVITEs Alice
  # with Contact <sip:2002-mixer@...>;isfocus, then INVITEs baresip 2003 (Carol, answers after 1.5 s) with the same
  # Contact; 6 s later Bob hangs up both calls
  confadd)  sipp_reg 2002 192.0.2.22
            uas uas-conf-add.xml 24 bob 2002 192.0.2.22 40000 -set third 2003 -auth_uri 2003@lab.sip
            phone 2003 192.0.2.23 $B3 50000 24 ";answermode=auto;answerdelay=1500"; phone 2001 192.0.2.21 $B1 30000 24
            sleep 3; dial $B1 sip:2002@lab.sip; sleep 18 ;;
  # RFC 5359 2.11 and RFC 3911: baresip 2001 (Alice) calls 2002 (Bob, SIPp, a phone that mixes); then 2003 (Carol,
  # SIPp: baresip refuses Join with 420) sends Bob an INVITE with Join (the Alice-Bob dialog, read from Bob's log) and
  # Require: join; Bob rings Carol, re-INVITEs Alice with his mixer Contact (isfocus) and answers Carol. Carol hangs up
  # 3 s later, Alice 2 s after her
  confjoin) sipp_reg 2002 192.0.2.22
            uas uas-conf-join.xml 30 bob 2002 192.0.2.22 40000 -m 2 -trace_logs -log_file captures/$NAME.bob.dialog.log
            phone 2001 192.0.2.21 $B1 30000 30; sleep 3; dial $B1 sip:2002@lab.sip; sleep 4
            J=$(grep -o 'JOIN-TARGET [^ ]*' captures/$NAME.bob.dialog.log | tail -1 | cut -d' ' -f2)
            sipp_reg 2003 192.0.2.23
            uac call-x.xml 14 carol 2003 192.0.2.23 50000 -auth_uri 2002@lab.sip -set callee 2002 \
              -set xhdr "Join: $J"$'\r\nRequire: join'
            ctl 2 $B1 hangup; sleep 2 ;;
  # RFC 5359 2.16 call pickup: 2001 (Alice, SIPp: baresip 1.1.0 ignores Replaces) calls baresip 2002 (Bob), which
  # rings; 3 s later 2003 (Bill, SIPp) fetches Bob's dialog state (SUBSCRIBE Event: dialog, Expires: 0) from the
  # proxy's presence server and sends Alice an INVITE with Replaces (early-only); Alice answers it and CANCELs her call
  # to Bob; she hangs up 4 s later
  pickup)   phone 2002 192.0.2.22 $B2 40000 30; sipp_reg 2001 192.0.2.21; sipp_reg 2003 192.0.2.23; sleep 2
            bg uac pickup-alice.xml 24 alice 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 \
              -oocsf $S/pickup-alice-ooc.xml -trace_logs -log_file captures/$NAME.alice.events.log
            sleep 4; uac pickup-bill.xml 16 bill 2003 192.0.2.23 50000 -auth_uri 2001@lab.sip -set target 2002
            bgwait ;;
  # RFC 5359 2.15 call park: 2001 (Alice) calls 2002 (Bob), both SIPp (baresip 1.1.0 ignores Replaces and sends no
  # out-of-dialog REFER); 3 s after answering Bob parks the call: REFER to the park server (SIPp at 192.0.2.30), which
  # INVITEs Alice with Replaces (her dialog with Bob ends), plays music and NOTIFYs Bob; 5 s later 2003 (Carol, SIPp)
  # fetches the parked dialog from the park server (SUBSCRIBE Event: dialog, Expires: 0) and INVITEs Alice with
  # Replaces; Alice leaves the park (BYE); Carol hangs up 4 s later
  park)     addr 192.0.2.30; sipp_reg 2001 192.0.2.21; sipp_reg 2002 192.0.2.22; sipp_reg 2003 192.0.2.23
            uas park-bob.xml 30 bob 2002 192.0.2.22 40000 -auth_uri park@lab.sip
            uas park-server.xml 30 parkserver park 192.0.2.30 33000 -m 2 -min_rtp_port 33000 -max_rtp_port 33099
            sleep 1
            bg uac park-alice.xml 30 alice 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 \
              -oocsf $S/park-alice-ooc.xml -callid_slash_ign -cid_str "%u-%p-%s"
            sleep 10; uac park-carol.xml 16 carol 2003 192.0.2.23 50000 -auth_uri park@lab.sip -set target park
            bgwait ;;
  # RFC 3725 Flow I: the controller (SIPp at 192.0.2.30) sets up a call between baresip 2001 (A, answers after 1 s)
  # and baresip 2002 (B, answers after 2.5 s: A resends its 200 meanwhile); A hangs up 6 s after B answered
  3pcc)     addr 192.0.2.30
            phone 2001 192.0.2.21 $B1 30000 20 ";answermode=auto;answerdelay=1000"
            phone 2002 192.0.2.22 $B2 40000 20 ";answermode=auto;answerdelay=2500"; sleep 3
            bg uac ctl-3pcc.xml 16 controller 3pcc 192.0.2.30 0 -set a 2001 -set b 2002
            sleep 10; ctl 0 $B1 hangup; sleep 2; bgwait ;;
  # RFC 5359 2.18 click to dial by REFER: "Bob's PC" (192.0.2.30) sends phone 2001 an out-of-dialog REFER, Refer-To
  # sip:2002@lab.sip, Refer-Sub: false (requests/refer-click-to-dial.sip, sipsend.py): baresip 1.1.0 answers 501
  clickrefer) addr 192.0.2.30; phone 2001 192.0.2.21 $B1 30000 10; phone 2002 192.0.2.22 $B2 40000 10 ";answermode=auto;answerdelay=1000"
            sleep 3; ./sipsend.py --src 192.0.2.30 192.0.2.21 requests/refer-click-to-dial.sip > captures/$NAME.sipsend.txt 2>&1
            sleep 3 ;;
  # RFC 5359 2.17 automatic redial: baresip 2003 calls baresip 2002 (Bob), which takes one call at a time
  # (call_max_calls 1); 2001 (Alice, SIPp) calls Bob: 486; she subscribes to Bob's dialog state at the proxy's presence
  # server; 2003 hangs up 4 s later; the NOTIFY shows Bob free and Alice calls again (Bob answers after 2 s)
  redial)   phone 2002 192.0.2.22 $B2 40000 30 ";answermode=auto;answerdelay=2000" "call_max_calls 1"
            phone 2003 192.0.2.23 $B3 50000 30; sipp_reg 2001 192.0.2.21; sleep 2; dial $B3 sip:2002@lab.sip; sleep 4
            bg uac redial-alice.xml 24 alice 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 -aa
            sleep 4; ctl 0 $B3 hangup; bgwait ;;
  # RFC 3428: SIPp 2001 sends a MESSAGE to baresip 2002 (200 OK) and one to 2003, who is not registered (the proxy
  # stores it: 202 Accepted); 3 s later baresip 2003 starts, registers and the proxy delivers it (200 OK)
  message)  phone 2002 192.0.2.22 $B2 40000 16; sleep 2
            uac msg-send.xml 8 msg2002 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 \
              -set body "Lunch at 12:30?"; sleep 1
            uac msg-send.xml 8 msg2003 2001 192.0.2.21 30000 -auth_uri 2003@lab.sip -set callee 2003 \
              -set body "Call me when you are back."; sleep 3
            phone 2003 192.0.2.23 $B3 50000 8; sleep 6 ;;
  # RFC 6086: SIPp 2001 calls SIPp 2002, both say Recv-Info: foo; 2002 sends an INFO of package foo (200 OK) and one of
  # package bar (469 Bad Info Package + Recv-Info: foo), then hangs up
  infopkg)  sipp_reg 2002 192.0.2.22; uas info-callee.xml 14 uas 2002 192.0.2.22 40000; sleep 1
            uac info-caller.xml 14 uac 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 ;;
  # RFC 6086 against a phone that takes no Info Package: SIPp 2001 calls baresip 2002 and sends it an INFO of package foo
  infophone) phone 2002 192.0.2.22 $B2 40000 14 ";answermode=auto;answerdelay=1000"; sleep 3
            uac info-legacy-peer.xml 10 uac 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 ;;
  # the legacy use of INFO (no Info Package): baresip 2001 with dtmfmode=info sends digits 1 2 3 # to baresip 2002
  infodtmf) phone 2002 192.0.2.22 $B2 40000 18 ";answermode=auto;answerdelay=1000"
            phone 2001 192.0.2.21 $B1 30000 18 ";dtmfmode=info"; sleep 3; dial $B1 sip:2002@lab.sip; sleep 4
            for d in 1 2 3 '#'; do ctl 0.6 $B1 sndcode "$d"; done; ctl 2 $B1 hangup; sleep 2 ;;
  # lesson 5.17, the ticket "the busy lamp stays red after the call ends": SIPp 2003 (a phone's busy-lamp key) watches
  # 2002 with Expires: 30 and never refreshes (nor unsubscribes); baresip 2001 calls baresip 2002 (answered after 2 s)
  # for ~40 s; the subscription runs out during the call (its last NOTIFY said confirmed) and the end of the call is
  # notified to no one. ticketfix: the same, but the phone refreshes after 15 s without a NOTIFY, so it gets the
  # terminated state when the call ends; it unsubscribes after the third quiet period.
  ticket|ticketfix)
            [ $CASE = ticket ] && { RF=0; ST=99; } || { RF=1; ST=3; }
            bg uac sub-watch.xml 80 watch 2003 192.0.2.23 50000 -auth_uri 2002@lab.sip -set target 2002 -set event dialog \
              -set accept application/dialog-info+xml -set expires 30 -set refresh $RF -set stopafter $ST -aa
            phone 2002 192.0.2.22 $B2 40000 60 ";answermode=auto;answerdelay=2000"; phone 2001 192.0.2.21 $B1 30000 60
            sleep 4; dial $B1 sip:2002@lab.sip; ctl 42 $B1 hangup; sleep 8
            [ $CASE = ticket ] || bgwait ;;
  # lesson 5.12, a real phone and Join: baresip 2001 calls baresip 2002 (answers after 2 s); SIPp 2003 sends 2002 an
  # INVITE with Join: <that call's Call-ID>;to-tag=<2002's tag>;from-tag=<2001's tag> and Require: join (the dialog read
  # from 2001's log); baresip 2002's answer is the take
  joinbaresip)
            phone 2002 192.0.2.22 $B2 40000 20 ";answermode=auto;answerdelay=2000"; phone 2001 192.0.2.21 $B1 30000 20
            sipp_reg 2003 192.0.2.23; sleep 2; dial $B1 sip:2002@lab.sip; sleep 4
            J=$(python3 - captures/$NAME.2001.log <<'PY'
import re, sys
t = open(sys.argv[1], errors="replace").read()
blocks = re.split(r"\n(?=(?:INVITE|ACK|BYE|CANCEL|SIP/2.0|REGISTER|NOTIFY|SUBSCRIBE|REFER|OPTIONS|INFO|MESSAGE) )", t)
cid = ftag = ttag = None
for b in blocks:
    if b.startswith("INVITE ") and cid is None:
        cid = re.search(r"Call-ID: (\S+)", b).group(1)
        ftag = re.search(r"\nFrom: [^\n]*;tag=([^;\s]+)", b).group(1)
    if cid and b.startswith("SIP/2.0 200") and "Call-ID: " + cid in b and " INVITE" in re.search(r"CSeq: [^\n]*", b).group(0):
        ttag = re.search(r"\nTo: [^\n]*;tag=([^;\s]+)", b).group(1)
        break
print(f"{cid};to-tag={ttag};from-tag={ftag}")
PY
)
            echo "Join: $J" > captures/$NAME.join.txt
            uac call-refusable.xml 10 uac 2003 192.0.2.23 50000 -auth_uri 2002@lab.sip -set callee 2002 \
              -set xhdr "Join: $J"$'\r\nRequire: join'
            ctl 2 $B1 hangup; sleep 2 ;;
  # lesson 5.10: fwdbusy again; the proxy adds Diversion: <sip:2002@lab.sip>;reason=user-busy to the INVITE to 2003
  histdiv)  sipp_reg 2002 192.0.2.22; uas uas-486.xml 12 uas 2002 192.0.2.22 40000
            phone 2003 192.0.2.23 $B3 50000 16 ";answermode=auto;answerdelay=1500"; phone 2001 192.0.2.21 $B1 30000 16
            sleep 3; dial $B1 sip:2002@lab.sip; ctl 8 $B1 hangup; sleep 2 ;;
  # lesson 5.10: the same call from a SIPp 2001 that supports History-Info (Supported: histinfo, its entry index=1);
  # baresip 2003 answers (it sends no History-Info back); 2001 hangs up 3 s after the answer
  histhi)   sipp_reg 2002 192.0.2.22; uas uas-486.xml 12 uas 2002 192.0.2.22 40000
            phone 2003 192.0.2.23 $B3 50000 16 ";answermode=auto;answerdelay=1500"; sleep 3; sipp_reg 2001 192.0.2.21
            uac call-x.xml 12 uac 2001 192.0.2.21 30000 -auth_uri 2002@lab.sip -set callee 2002 \
              -set xhdr $'Supported: histinfo\r\nHistory-Info: <sip:2002@lab.sip>;index=1'; sleep 2 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
rm -rf /tmp/lab-presence
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap -o rtp.heuristic_rtp:TRUE -Y "rtp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
(cd captures && python3 ../pcap_messages.py "$NAME.pcap" >/dev/null)
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
cat captures/$NAME.txt; echo "=== rtp ==="; cat captures/$NAME.rtp.txt
