#!/bin/bash
# sip-lab takes for section 7 part B (SIP at scale: SBC, load balancing, high availability, transports, IPv6, load
# testing, monitoring, and a ticket about a second server). Everything stays on the box: documentation addresses
# (192.0.2.x, 198.51.100.x, 2001:db8::/32), lab-made certificates, SIPp and baresip as the phones, OpenSIPS 4.0 as every
# server.
#   sudo ./take-scale.sh <case> <name>
# Cases (lesson): topohide (7.6), lb (7.7), ha (7.8), transport (7.9), ipv6 (7.10), load (7.11), hep (7.12),
# ticket ticketfix (7.13).
# Roles: lab.cfg (192.0.2.10, domain lab.sip) = the proxy / SBC / front; phones 2001-2003 = 192.0.2.21-.23 (baresip, or
# SIPp where a scripted UA is needed); added for a take (removed after): back-ends 192.0.2.31/.32 (lb, ticket), the two HA
# nodes 192.0.2.11/.12 in namespaces (ha), IPv6 2001:db8::10/21/22 (ipv6), the HEP collector 192.0.2.60 (hep, transport).
# Each case writes captures/<name>.pcap, .txt (SIP summary), .messages.txt (pcap_messages.py for UDP over IPv4; the
# take's own decoder for TCP, TLS through HEP, and IPv6), .rtp.txt, .media.txt, the logs of every element, .cfg.diff when
# a cfg changes, and per case .mi.txt, .terminal.txt, .hep.txt, .stats.txt, .cdr.txt. Leaves nothing running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
# what an interrupted take may have left (net.sh puts the addresses back)
for n in ph21 ph22 nodea nodeb; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done
for l in phbr habr; do ip link del $l 2>/dev/null; iptables -D INPUT -i $l -j ACCEPT 2>/dev/null; done
./net.sh >/dev/null
for p in opensips baresip sipp rtpengine; do pkill -x $p 2>/dev/null; done
[ -f /tmp/lab-hep-sink.pid ] && kill $(cat /tmp/lab-hep-sink.pid) 2>/dev/null; rm -f /tmp/lab-hep-sink.pid; sleep 1
mkdir -p /run/opensips
S=scenarios
ADDRS=()   # addresses this take added to lab0
rm -f captures/$NAME.*

CFG=/tmp/lab-take.cfg; sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > $CFG
PLAIN=/tmp/lab-take-plain.cfg; cp $CFG $PLAIN
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
edit() { editf $CFG "$1" "$2"; }
MODS=$'loadmodule "proto_udp.so"\n'
mods() { edit "$MODS" "$MODS"$'\n'"$1"; }   # mods <lines>: more modules after proto_udp
routes() { edit $'\n# the lab\'s users' "$1"$'\n# the lab\'s users'; }
users() {  # users <user:password>...: extra lab users
  local up lines=""
  for up in "$@"; do lines+=$'\t\tcase "'${up%%:*}$'": $avp(passspec) = "'${up#*:}$'"; break;\n'; done
  edit $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n' \
       $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n'"$lines"
}
addr() { ip addr add "$1/32" dev lab0 2>/dev/null; ADDRS+=("$1"); }
mi() {  # mi <fifo> <command> [args]: an MI command, its output appended to <name>.mi.txt
  local fifo=$1; shift
  { echo "## $(date +%T) opensips-cli -x mi $*"
    opensips-cli -o fifo_file=$fifo -x mi "$@" 2>&1 | sed "s/\x1b\[[0-9;]*m//g"; echo; } >> captures/$NAME.mi.txt
}
FIFO=/run/opensips/opensips_fifo

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] ["key value" config line]...: PCMU only
  local u=$1 ip=$2 c=$3 r=$4 t=$5 p=${6:-} d kv k v; shift 5; [ $# -gt 0 ] && shift
  d=$(./baresip-phone.sh "$u" "$ip" "$c" "$r" ";audio_codecs=PCMU/8000/1$p")
  [ -n "${NOREG:-}" ] && sed -i "s|regint=3600|regint=0|" "$d/accounts"   # NOREG=1: the phone does not register
  [ -n "${TRANSPORT:-}" ] && sed -i "s|@lab.sip>|@lab.sip;transport=$TRANSPORT>|" "$d/accounts"   # TRANSPORT=tcp|tls
  for kv in "$@"; do  # replace the key's line, commented or not (baresip reads the first one), or add it
    k=${kv%% *} v=${kv#* }
    if grep -q "^#\?$k[[:space:]]" "$d/config"; then sed -i "0,/^#\?$k[[:space:]].*/s||$k\t\t$v|" "$d/config"
    else printf '%s\t\t%s\n' "$k" "$v" >> "$d/config"; fi
  done
  # PHNS=1: the phone runs in its own network namespace ph<last octet> (phns_up), a host of its own: its TCP/TLS
  # connections leave from its address (in the root namespace the kernel gives a connection to 192.0.2.10 the source
  # 192.0.2.10, and baresip writes that into its Contact)
  local ns=""; [ -n "${PHNS:-}" ] && ns="ip netns exec ph${ip: -2}"
  timeout "$t" $ns baresip -f "$d" -t "$t" -s > captures/$NAME.$u.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip> [port]
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p "${3:-5060}" -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
bctl() {  # bctl <ctrl port> <command...>: bctl.py, inside the phone's namespace when PHNS=1 (port 44NN = phone 20NN)
  local ns=""; [ -n "${PHNS:-}" ] && ns="ip netns exec ph2${1: -1}"
  $ns ./bctl.py "$@" >> captures/$NAME.ctl.log 2>&1
}
phbr_up() {  # phones 2001 and 2002 as hosts of their own: namespaces ph21/ph22 (phns_up) on a bridge phbr; the proxy
  # stays in the root namespace and answers ARP for 192.0.2.10 on the bridge. V6=1: the phones are IPv6-only
  # (2001:db8::21/22) and the proxy's IPv6 address 2001:db8::10 sits on the bridge (IPv6 neighbour discovery answers
  # only for an address of the interface asked)
  ip link add phbr type bridge; ip link set phbr up
  ip addr add 192.0.2.1/32 dev phbr; sysctl -q -w net.ipv4.conf.phbr.arp_announce=2   # see habr in the ha case
  if [ -n "${V6:-}" ]; then
    ip addr add 2001:db8::10/128 dev phbr nodad
    for a in 21 22; do ip -6 route add 2001:db8::$a/128 dev phbr; done
    ip6tables -I INPUT -i phbr -j ACCEPT
  else
    for a in 21 22; do ip addr del 192.0.2.$a/32 dev lab$a; ip route add 192.0.2.$a/32 dev phbr; done
  fi
  iptables -I INPUT -i phbr -j ACCEPT
}
phbr_down() {
  if [ -n "${V6:-}" ]; then ip6tables -D INPUT -i phbr -j ACCEPT
  else for a in 21 22; do ip route del 192.0.2.$a/32 dev phbr 2>/dev/null; ip addr add 192.0.2.$a/32 dev lab$a; done; fi
  ip link del phbr; iptables -D INPUT -i phbr -j ACCEPT
}
phns_up() {
  for a in 21 22; do
    ip netns add ph$a; ip link add vp$a type veth peer name tmp$a netns ph$a
    ip -n ph$a link set tmp$a name lab$a   # named like the root's dummy, so baresip's net_interface fits
    ip link set vp$a master phbr; ip link set vp$a up
    ip -n ph$a link set lo up; ip -n ph$a link set lab$a up
    if [ -n "${V6:-}" ]; then
      ip -n ph$a addr add 2001:db8::$a/128 dev lab$a nodad; ip -n ph$a -6 route add 2001:db8::/64 dev lab$a
    else
      ip -n ph$a addr add 192.0.2.$a/32 dev lab$a; ip -n ph$a route add 192.0.2.0/24 dev lab$a
    fi
  done
}
phns_down() {  # the namespaces go, and every socket in them (TIME_WAIT included: the next phone can bind 5060 again)
  for a in 21 22; do ip netns pids ph$a | xargs -r kill 2>/dev/null; done; sleep 1
  for a in 21 22; do ip link del vp$a; ip netns del ph$a; done   # the veth first: a namespace goes away in its own time
}
T=captures/$NAME.terminal.txt
term() {  # term <command>: typed as user lab in ~/lab; the prompt, the command and its output go to the terminal file
  printf 'lab@sip-lab:~/lab$ %s\n' "$1" >> $T
  env -i HOME=/home/lab USER=lab LOGNAME=lab PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    setpriv --reuid=lab --regid=lab --init-groups bash -c "cd /home/lab/lab; $1" 2>&1 | sed "s/\x1b\[[0-9;]*m//g" >> $T
}
note() { printf '%s\n' "$1" >> $T; }   # a line the student does not type (a pause, a comment)

# the take's own decoders (TCP, IPv6 and HEP are beyond pcap_messages.py), written for the take and removed after
cat > /tmp/lab-decode.py <<'EOF'
"""lab-decode.py sip|hep <pcap> <out>: every SIP message (UDP or TCP, IPv4 or IPv6, CRLF keepalives marked) or
every HEPv3 packet (header chunks + the SIP it carries) in the pcap, in the format of pcap_messages.py."""
import socket, subprocess, sys
mode, pcap, out = sys.argv[1:4]
def tshark(flt, fields):
    cmd = ["tshark", "-r", pcap, "-Y", flt, "-T", "fields", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    return [l.split("\t") for l in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()]
blocks = []
if mode == "sip":
    rows = tshark("(udp.port == 5060 or tcp.port == 5060 or tcp.port == 5061) and (udp.length > 8 or tcp.len > 0)",
                  ["frame.number", "frame.time_relative", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport",
                   "tcp.dstport", "udp.srcport", "udp.dstport", "udp.payload", "tcp.payload"])
    for n, t, s4, s6, d4, d6, tsp, tdp, usp, udp_, up, tp in rows:
        proto = "TCP" if tp else "UDP"
        src, dst = (s4 or f"[{s6}]") + ":" + (tsp or usp), (d4 or f"[{d6}]") + ":" + (tdp or udp_)
        raw = bytes.fromhex((up or tp).replace(":", ""))
        if (tsp or usp) == "5061" or (tdp or udp_) == "5061":
            text = f"[TLS, {len(raw)} bytes, encrypted]"
        elif raw.strip(b"\r\n") == b"":
            text = "[keepalive: " + raw.decode().replace("\r", "CR ").replace("\n", "LF ").strip() + "]"
        else:
            text = raw.decode("utf-8", "replace").replace("\r\n", "\n").strip()
        blocks.append(f"===== frame {n}  t={float(t):.3f}s  {proto} {src} -> {dst}\n{text}\n")
else:
    names = {1: "ip family", 2: "ip protocol", 3: "src ip", 4: "dst ip", 5: "src ip", 6: "dst ip", 7: "src port",
             8: "dst port", 9: "time (s)", 10: "time (us)", 11: "payload type", 12: "capture agent id",
             14: "auth key", 15: "payload", 17: "correlation id"}
    for n, t, s, d, up in tshark("udp.dstport == 9060", ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
                                                        "udp.payload"]):
        b = bytes.fromhex(up.replace(":", ""))
        lines, payload, pos = [f"HEP header: {b[:4].decode()} length {int.from_bytes(b[4:6], 'big')}"], "", 6
        while pos + 6 <= len(b):
            vendor, typ, ln = (int.from_bytes(b[pos + i:pos + i + 2], "big") for i in (0, 2, 4))
            v = b[pos + 6:pos + ln]; pos += ln
            if typ in (3, 4):
                val = socket.inet_ntop(socket.AF_INET, v)
            elif typ in (5, 6):
                val = socket.inet_ntop(socket.AF_INET6, v)
            elif typ == 15:
                payload = v.decode("utf-8", "replace").replace("\r\n", "\n").strip(); val = f"{len(v)} bytes (below)"
            elif typ in (14, 17):
                val = v.decode("utf-8", "replace")
            else:
                val = str(int.from_bytes(v, "big"))
                if typ == 1: val += " (IPv4)" if val == "2" else " (IPv6)" if val == "10" else ""
                if typ == 2: val += {"6": " (TCP)", "17": " (UDP)"}.get(val, "")
                if typ == 11: val += " (SIP)" if val == "1" else ""
            lines.append(f"  chunk {typ:>2} {names.get(typ, '?'):<17} {val}")
        blocks.append(f"===== frame {n}  t={float(t):.3f}s  HEP {s} -> {d}\n" + "\n".join(lines) + f"\n{payload}\n")
open(out, "w").write("\n".join(blocks))
print(f"{out}: {len(blocks)} messages")
EOF

DIRECT=1     # 1 = the proxy runs from $CFG in the root namespace after the case set-up
CAPIF=lo; CAPF='udp or icmp'
case $CASE in
  # lesson 7.6: an SBC. The same call 2001 -> 2002 twice: first through plain lab.cfg (a proxy: the callee sees the
  # caller's Via, Contact, Call-ID, the proxy's Record-Route and the caller's SDP), then through lab.cfg with
  # topology_hiding("C") (dialog-based: Via, Record-Route and Route stripped and restored, Contact = the SBC, the
  # Call-ID encoded toward the callee), rtpengine anchoring the media (c= and m= = the SBC's address and ports) and one
  # normalization (User-Agent and Server removed: the vendor and version of the phones stay inside).
  topohide)
    DIRECT=0
    edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# lesson 7.6: an SBC: topology hiding (on top of the dialog module) and a media relay\nloadmodule "dialog.so"\nloadmodule "topology_hiding.so"\nloadmodule "rtpengine.so"\nmodparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")\n'
    edit $'\tif (has_totag()) {\n\t\tif (loose_route()) {\n\t\t\tt_relay();\n' $'\tif (has_totag()) {\n\t\t# lesson 7.6: an in-dialog request carries no Route to us (topology hiding removed them): match it by its dialog\n\t\tif (topology_hiding_match()) {\n\t\t\tif (is_method("BYE"))\n\t\t\t\trtpengine_delete();\n\t\t\troute(normalize);\n\t\t\tt_relay();\n\t\t} else if (loose_route()) {\n\t\t\tt_relay();\n'
    edit $'\trecord_route();\n\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\tt_relay();\n}' $'\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\tif (is_method("INVITE")) {\n\t\t# lesson 7.6: the SBC. Topology hiding: Via, Record-Route and Contact of the caller\'s side stay on that side, the\n\t\t# Call-ID is encoded toward the callee (C); media anchoring: the SDP gets the SBC\'s address and ports\n\t\tcreate_dialog();\n\t\ttopology_hiding("C");\n\t\trtpengine_offer("replace-origin");\n\t\troute(normalize);\n\t\tt_on_reply("sbc");\n\t} else {\n\t\trecord_route();\n\t}\n\tt_relay();\n}\n\n# lesson 7.6: normalization: the phones\' vendor and version do not leave the SBC\nroute[normalize] {\n\tremove_hf("User-Agent");\n}\n\nonreply_route[sbc] {\n\tif (has_body("application/sdp"))\n\t\trtpengine_answer("replace-origin");\n\tremove_hf("User-Agent");\n\tremove_hf("Server");\n}'
    ;;
  # lesson 7.7: a front proxy spreading calls over two back-ends (dispatcher set 1, algorithm 4 = round robin), each
  # back-end pinged with OPTIONS every 5 s; threshold 2 failed pings = probing (down). Calls to sip:8000@lab.sip (the
  # back-ends' service number) go to the back-ends. A back-end that does not answer an INVITE: tm's timer fires (408),
  # failure_route marks it and sends the call to the other one. Back-ends = SIPp UASes at 192.0.2.31 and .32.
  lb|ticket|ticketfix)
    addr 192.0.2.31; addr 192.0.2.32
    mkdir -p /tmp/lab-scale; rm -f /tmp/lab-scale/*; cp /usr/share/opensips/dbtext/opensips/dispatcher /tmp/lab-scale/
    cp /usr/share/opensips/dbtext/opensips/version /tmp/lab-scale/
    printf '%s\n' '1:1:sip\:192.0.2.31\:5060::0:1:1:0::back-end 1' '2:1:sip\:192.0.2.32\:5060::0:1:1:0::back-end 2' \
      >> /tmp/lab-scale/dispatcher
    ;;&
  lb)
    mods $'# lesson 7.7: two back-ends in dispatcher set 1 (table "dispatcher" in /tmp/lab-scale), pinged with OPTIONS\nloadmodule "db_text.so"\nloadmodule "dispatcher.so"\nmodparam("dispatcher", "db_url", "text:///tmp/lab-scale")\nmodparam("dispatcher", "ds_ping_method", "OPTIONS")\nmodparam("dispatcher", "ds_ping_from", "sip:lb@lab.sip")\nmodparam("dispatcher", "ds_ping_interval", 5)\nmodparam("dispatcher", "ds_probing_threshold", 2)\nmodparam("dispatcher", "ds_probing_mode", 1)\n'
    edit $'\trecord_route();\n\tif (!lookup("location")) {' $'\trecord_route();\n\t# lesson 7.7: the service number lives on the back-ends: one of them, round robin (algorithm 4); keep the\n\t# others for failover (flag f)\n\tif ($rU == "8000") {\n\t\tif (!ds_select_dst(1, 4, "f")) {\n\t\t\tsend_reply(503, "Service Unavailable");\n\t\t\texit;\n\t\t}\n\t\txlog("L_NOTICE", "lb: call $ci to $du\\n");\n\t\tt_on_failure("lb_failover");\n\t\tt_relay();\n\t\texit;\n\t}\n\tif (!lookup("location")) {'
    routes $'\n# lesson 7.7: a back-end changed state (pings failed, or it answers again)\nevent_route[E_DISPATCHER_STATUS] {\n\txlog("L_NOTICE", "dispatcher: set $param(group) destination $param(address) is now $param(status)\\n");\n}\n\n# lesson 7.7: the back-end did not answer the INVITE (tm gave up: 408) or failed (5xx): mark it, try the next one\nfailure_route[lb_failover] {\n\tif (t_was_cancelled())\n\t\texit;\n\tif (t_check_status("408|5[0-9][0-9]")) {\n\t\txlog("L_NOTICE", "lb: $du gave $T_reply_code, marking it probing\\n");\n\t\tds_mark_dst("p");\n\t\tif (ds_next_dst()) {\n\t\t\txlog("L_NOTICE", "lb: call $ci now to $du\\n");\n\t\t\tt_on_failure("lb_failover");\n\t\t\tt_relay();\n\t\t}\n\t}\n}\n'
    ;;
  # lesson 7.8: two OpenSIPS nodes (lab.cfg + clusterer) share registrations (usrloc full-sharing-cluster) and dialogs
  # (dialog replication, sharing tag "vip"); the service address 192.0.2.10 belongs to the active node. Each node is a
  # network namespace (nodea = 192.0.2.11, nodeb = 192.0.2.12) on a bridge (habr) in the root namespace, where the
  # phones live; the nodes talk BIN (TCP 5566) to each other. Node B binds 192.0.2.10 before it has it
  # (ip_nonlocal_bind). Node A dies (kill -9, its link down); the take then does what keepalived would: 192.0.2.10 on
  # node B, a gratuitous ARP, node B's sharing tag set active.
  ha)
    DIRECT=0; CAPIF=habr; CAPF='udp or icmp or arp or tcp port 5566'
    LAB0=$(ip -o -4 addr show lab0 | awk '$4 ~ /^192\.0\.2\.10\// {print $4}')   # put back as it was
    ip addr del $LAB0 dev lab0
    ip link add habr type bridge; ip link set habr up
    # a lab address of the root's own on the bridge: an ARP request the root sends there names it (with no address on
    # the bridge the kernel took the droplet's public address as the sender, 2026-10-30)
    ip addr add 192.0.2.1/32 dev habr; sysctl -q -w net.ipv4.conf.habr.arp_announce=2
    for n in a b; do
      ip netns add node$n; ip link add ha-$n type veth peer name ha0 netns node$n
      ip link set ha-$n master habr; ip link set ha-$n up
      ip -n node$n link set lo up; ip -n node$n link set ha0 up
      ip -n node$n route add 192.0.2.0/24 dev ha0
    done
    ip -n nodea addr add 192.0.2.11/32 dev ha0; ip -n nodea addr add 192.0.2.10/32 dev ha0
    ip -n nodeb addr add 192.0.2.12/32 dev ha0
    ip netns exec nodeb sysctl -q -w net.ipv4.ip_nonlocal_bind=1
    for a in 10 11 12; do ip route add 192.0.2.$a/32 dev habr; done
    iptables -I INPUT -i habr -j ACCEPT
    addr 192.0.2.24; users 2004:lab-2004-pass
    hacfg() {  # hacfg <letter> <node id> <own address> <peer id> <peer address> <active|backup>
      local f=/tmp/lab-node$1.cfg; cp $CFG $f
      editf $f $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\t# the service address: it lives on the active node\nsocket=bin:'"$3"$':5566\t\t# node to node (clusterer)\n'
      editf $f '/run/opensips/opensips_fifo' "/run/opensips/node$1_fifo"
      editf $f 'modparam("usrloc", "working_mode_preset", "single-instance-no-db")' $'modparam("usrloc", "working_mode_preset", "full-sharing-cluster")\t# lesson 7.8: every registration on every node\nmodparam("usrloc", "location_cluster", 1)'
      local seed=""; [ $2 = 1 ] && seed=", flags=seed"
      editf $f "$MODS" "$MODS"$'\n# lesson 7.8: a cluster of two nodes (no database: the nodes are listed here)\nloadmodule "proto_bin.so"\nloadmodule "clusterer.so"\nmodparam("clusterer", "db_mode", 0)\nmodparam("clusterer", "my_node_id", '"$2"$')\nmodparam("clusterer", "my_node_info", "cluster_id=1, url=bin:'"$3"$':5566'"$seed"$'")\nmodparam("clusterer", "neighbor_node_info", "cluster_id=1, node_id='"$4"$', url=bin:'"$5"$':5566")\nmodparam("clusterer", "ping_interval", 1)\nmodparam("clusterer", "ping_timeout", 500)\nmodparam("clusterer", "sharing_tag", "vip/1='"$6"$'")\nloadmodule "dialog.so"\nmodparam("dialog", "dialog_replication_cluster", 1)\n'
      editf $f $'\tif (has_totag()) {\n' $'\tif (has_totag()) {\n\t\txlog("L_NOTICE", "node '"$1"$': in-dialog $rm for $ci\\n");\n'
      editf $f $'\t\tif (t_check_trans())\n\t\t\tt_relay();\n\t\texit;' $'\t\tif (t_check_trans())\n\t\t\tt_relay();\n\t\telse\n\t\t\txlog("L_NOTICE", "node '"$1"$': CANCEL for $ci: no such transaction here\\n");\n\t\texit;'
      editf $f $'\trecord_route();\n\tif (!lookup' $'\t# lesson 7.8: the call is a dialog shared with the other node, owned by whichever node holds "vip"\n\tif (is_method("INVITE")) {\n\t\tcreate_dialog();\n\t\tset_dlg_sharing_tag("vip");\n\t\txlog("L_NOTICE", "node '"$1"$': new call $ci\\n");\n\t}\n\trecord_route();\n\tif (!lookup'
    }
    hacfg a 1 192.0.2.11 2 192.0.2.12 active
    hacfg b 2 192.0.2.12 1 192.0.2.11 backup
    diff opensips/lab.cfg /tmp/lab-nodea.cfg > captures/$NAME.cfg.diff; diff /tmp/lab-nodea.cfg /tmp/lab-nodeb.cfg > captures/$NAME.nodeb.cfg.diff
    # a gratuitous ARP (what keepalived sends when it takes the address): "192.0.2.10 is at <my MAC>"
    cat > /tmp/lab-garp.py <<'EOF'
import socket, sys
ifname, ip = sys.argv[1], socket.inet_aton(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((ifname, 0))
mac = s.getsockname()[4]
arp = b"\x00\x01\x08\x00\x06\x04\x00\x01" + mac + ip + b"\x00" * 6 + ip
s.send(b"\xff" * 6 + mac + b"\x08\x06" + arp + b"\x00" * 18)
EOF
    ;;
  # lesson 7.9: one proxy listening on UDP 5060, TCP 5060 and TLS 5061 (lab CA, a certificate for lab.sip and
  # 192.0.2.10; TLS 1.2 and up), baresip phones registering and calling over each in turn. Every message the proxy
  # handles is mirrored as HEP to 192.0.2.60:9060, so the TLS legs can be read (tracer, proto_hep). Two runs of the cfg:
  # "plain" (as above) and "reuse" (force_tcp_alias(): RFC 5923 connection reuse for requests that arrive over TCP/TLS,
  # and a registrar answer with Require: outbound + Flow-Timer: 15 for a phone that asks for RFC 5626 outbound).
  transport)
    DIRECT=0; CAPIF=phbr; CAPF='udp or tcp port 5060 or tcp port 5061 or icmp'; phbr_up
    addr 192.0.2.60
    D=/tmp/lab-tls; rm -rf $D; mkdir -p $D
    openssl ecparam -name prime256v1 -genkey -noout -out $D/ca.key
    openssl req -x509 -new -key $D/ca.key -subj "/CN=sip-lab CA (lab only)" -days 30 -out $D/ca.pem
    openssl ecparam -name prime256v1 -genkey -noout -out $D/server.key
    openssl req -new -key $D/server.key -subj "/CN=lab.sip" -out $D/server.csr
    printf 'subjectAltName=DNS:lab.sip,IP:192.0.2.10\nextendedKeyUsage=serverAuth\n' > $D/ext.cnf
    openssl x509 -req -in $D/server.csr -CA $D/ca.pem -CAkey $D/ca.key -CAcreateserial -days 30 -extfile $D/ext.cnf \
      -out $D/server.pem 2>/dev/null
    chmod 644 $D/*.pem
    { echo "# the lab CA and the proxy's certificate (made for the take, valid 30 days; the private keys are not kept)"
      openssl x509 -in $D/ca.pem -noout -subject -issuer -dates; echo
      openssl x509 -in $D/server.pem -noout -text; } > captures/$NAME.tls.txt
    edit $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\nsocket=tcp:192.0.2.10:5060\t# lesson 7.9: TCP\nsocket=tls:192.0.2.10:5061\t# lesson 7.9: TLS\nsocket=hep_udp:192.0.2.10:9061\t# lesson 7.9: HEP mirror of what the proxy handles\n'
    mods $'# lesson 7.9: TCP and TLS (lab CA and certificate in /tmp/lab-tls), and a HEP mirror to 192.0.2.60:9060\nloadmodule "proto_tcp.so"\nloadmodule "proto_tls.so"\nloadmodule "tls_openssl.so"\nloadmodule "tls_mgm.so"\nmodparam("tls_mgm", "server_domain", "lab")\nmodparam("tls_mgm", "match_ip_address", "[lab]192.0.2.10:5061")\nmodparam("tls_mgm", "certificate", "[lab]/tmp/lab-tls/server.pem")\nmodparam("tls_mgm", "private_key", "[lab]/tmp/lab-tls/server.key")\nmodparam("tls_mgm", "ca_list", "[lab]/tmp/lab-tls/ca.pem")\nmodparam("tls_mgm", "tls_method", "[lab]TLSv1_2-")\nmodparam("tls_mgm", "verify_cert", "[lab]0")\nmodparam("tls_mgm", "require_cert", "[lab]0")\nmodparam("tls_mgm", "client_domain", "phones")\nmodparam("tls_mgm", "match_ip_address", "[phones]*")\nmodparam("tls_mgm", "verify_cert", "[phones]0")\nloadmodule "proto_hep.so"\nmodparam("proto_hep", "hep_id", "[collector]192.0.2.60:9060; transport=udp; version=3")\nloadmodule "tracer.so"\nmodparam("tracer", "trace_id", "[lab]uri=hep:collector")\n'
    edit $'route {\n' $'route {\n\t# lesson 7.9: mirror every request and its transaction (replies included) to the HEP collector\n\tif (is_method("ACK"))\n\t\ttrace("lab", "m");\n\telse\n\t\ttrace("lab", "t");\n'
    REUSE=/tmp/lab-take-reuse.cfg; cp $CFG $REUSE
    editf $REUSE $'\t\ttrace("lab", "t");\n' $'\t\ttrace("lab", "t");\n\t# lesson 7.9, RFC 5923: a request that came over TCP/TLS: later requests to the address and port in its Via go\n\t# back over the same connection (an alias for it), not a new one\n\tif ($(socket_in(proto){s.tolower}) == "tcp" || $(socket_in(proto){s.tolower}) == "tls")\n\t\tforce_tcp_alias();\t# the manual warns: for trusted peers only (phones behind one public address = call hijacking)\n'
    editf $REUSE $'\t\tif (!save("location"))' $'\t\t# lesson 7.9, RFC 5626: a phone that asks for outbound gets it, with a keepalive every 15 s or less\n\t\tif ($hdr(Supported) =~ "outbound")\n\t\t\tappend_to_reply("Require: outbound\\r\\nFlow-Timer: 15\\r\\n");\n\t\tif (!save("location"))'
    diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff; diff $CFG $REUSE > captures/$NAME.reuse.cfg.diff
    for c in $CFG $REUSE; do /usr/sbin/opensips -C -f $c > /tmp/lab-check.txt 2>&1 || { cat /tmp/lab-check.txt; exit 1; }; done
    ;;
  # lesson 7.10: the proxy is dual stack (192.0.2.10 and 2001:db8::10); phones 2001 and 2002 are IPv6-only hosts
  # (namespaces, 2001:db8::21/22, baresip with an outbound proxy [2001:db8::10]); phone 2003 is IPv4-only (192.0.2.23).
  # Runs: "plain" (lab.cfg + the IPv6 socket): 2001 -> 2002 over IPv6, then 2001 -> 2003 (an IPv6 offer to an IPv4-only
  # phone); "bridge" (+ rtpengine on both families, address-family=IP4 toward an IPv4 callee of an IPv6 caller, IP6
  # back): 2001 -> 2003 again.
  ipv6)
    DIRECT=0; V6=1; CAPIF=phbr; CAPF='udp or icmp or icmp6'; phbr_up
    edit $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\nsocket=udp:[2001:db8::10]:5060\t# lesson 7.10: the proxy\'s IPv6 address\n'
    BRIDGE=/tmp/lab-take-bridge.cfg; cp $CFG $BRIDGE
    editf $BRIDGE "$MODS" "$MODS"$'\n# lesson 7.10: rtpengine relays between the families\nloadmodule "rtpengine.so"\nmodparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")\n'
    editf $BRIDGE $'\t\tif (loose_route()) {\n' $'\t\tif (is_method("BYE"))\n\t\t\trtpengine_delete();\n\t\tif (loose_route()) {\n'
    editf $BRIDGE $'\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\tt_relay();\n}' $'\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\t# lesson 7.10: an IPv6 caller, an IPv4 callee: the callee gets an IPv4 offer (rtpengine), the caller an IPv6 answer\n\tif (is_method("INVITE") && $si =~ ":" && !($rd =~ ":")) {\n\t\trtpengine_offer("replace-origin address-family=IP4");\n\t\tt_on_reply("bridge");\n\t}\n\tt_relay();\n}\n\nonreply_route[bridge] {\n\tif (has_body("application/sdp"))\n\t\trtpengine_answer("replace-origin address-family=IP6");\n}'
    diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff; diff $CFG $BRIDGE > captures/$NAME.bridge.cfg.diff
    for c in $CFG $BRIDGE; do /usr/sbin/opensips -C -f $c > /tmp/lab-check.txt 2>&1 || { cat /tmp/lab-check.txt; exit 1; }; done
    ;;
  # lesson 7.13: "calls fail at hang-up after we added a second server". The front (lab.cfg at 192.0.2.10) spreads EVERY
  # request over two SBC nodes (dispatcher set 1, 192.0.2.31/.32, opensips/sbc-node.cfg): round robin per request
  # (algorithm 4) in the ticket, by a hash of the Call-ID (algorithm 0: every request of a call to the same node) in the
  # fix. Each node keeps its calls' dialog state (topology hiding) and advertises the front's address in Contact, so
  # every in-dialog request comes back through the front. The phones do not register (the nodes know them).
  ticket|ticketfix)
    ALG=4; [ $CASE = ticketfix ] && ALG=0
    mods $'# lesson 7.13: the front: two SBC nodes in dispatcher set 1 (table "dispatcher" in /tmp/lab-scale)\nloadmodule "db_text.so"\nloadmodule "dispatcher.so"\nmodparam("dispatcher", "db_url", "text:///tmp/lab-scale")\n'
    if [ $ALG = 4 ]; then HOW='round robin (algorithm 4): request by request'; else HOW='by a hash of the Call-ID (algorithm 0): every request of a call to the same node'; fi
    edit $'\tif (has_totag()) {\n' $'\t# lesson 7.13: the front spreads every request (initial and in-dialog) over the SBC nodes, '"$HOW"$'\n\tif (!is_method("REGISTER")) {\n\t\tif (!has_totag())\n\t\t\tloose_route();\t# the phone\'s outbound-proxy Route (us) is used up here\n\t\tif (!ds_select_dst(1, '"$ALG"$')) {\n\t\t\tsend_reply(503, "Service Unavailable");\n\t\t\texit;\n\t\t}\n\t\txlog("L_NOTICE", "front: $rm $ci -> $du\\n");\n\t\tt_relay();\n\t\texit;\n\t}\n\n\tif (has_totag()) {\n'
    for n in 1 2; do sed -e "s/@NAME@/sbc$n/g" -e "s/@IP@/192.0.2.3$n/g" opensips/sbc-node.cfg > /tmp/lab-sbc$n.cfg; done
    ;;
  # lesson 7.11: lab.cfg as it is; SIPp UAC (192.0.2.21, From sipp@192.0.2.21: no digest, lab.cfg challenges only
  # From lab.sip) -> OpenSIPS -> SIPp UAS registered as 2002 (192.0.2.22), at 10, 50, 100 and 200 calls per second for
  # 10 s each, every call 2 s long.
  load) CAPF='udp port 5060 and host 192.0.2.21'; SNAP=300 ;;   # thousands of calls: the caller's side only, 300 bytes of each packet
  # lesson 7.12: lab.cfg + a HEP mirror of every call (proto_hep + tracer, dialog scope, SIP and the script's xlog lines)
  # to a collector at 192.0.2.60:9060 + acc CDRs (db_flatstore, /tmp/lab-acc) for the same calls.
  hep)
    addr 192.0.2.60; addr 192.0.2.24; users 2004:lab-2004-pass; mkdir -p /tmp/lab-acc; rm -f /tmp/lab-acc/*
    edit $'socket=udp:192.0.2.10:5060\n' $'socket=udp:192.0.2.10:5060\nsocket=hep_udp:192.0.2.10:9061\t# lesson 7.12: the HEP sending socket\n'
    mods $'# lesson 7.12: every call mirrored as HEPv3 to the collector (tracer, dialog scope) and a CDR per call (acc)\nloadmodule "proto_hep.so"\nmodparam("proto_hep", "hep_id", "[collector]192.0.2.60:9060; transport=udp; version=3")\nmodparam("proto_hep", "hep_capture_id", 1010)\nloadmodule "tracer.so"\nmodparam("tracer", "trace_id", "[homer]uri=hep:collector")\nloadmodule "dialog.so"\nloadmodule "db_flatstore.so"\nloadmodule "acc.so"\nmodparam("acc", "db_url", "flatstore:/tmp/lab-acc")\nmodparam("acc", "extra_fields", "db: caller; callee; src_ip; user_agent")\n'
    edit $'\trecord_route();\n\tif (!lookup("location")) {' $'\t# lesson 7.12: the whole call to the collector, SIP and the script\'s log lines; a CDR when it ends (or fails)\n\tif (is_method("INVITE")) {\n\t\ttrace("homer", "d", "sip|xlog");\n\t\tdo_accounting("db", "cdr|failed");\n\t\t$acc_extra(caller) = $fU;\n\t\t$acc_extra(callee) = $rU;\n\t\t$acc_extra(src_ip) = $si;\n\t\t$acc_extra(user_agent) = $ua;\n\t\txlog("L_NOTICE", "call $ci from $fU to $rU\\n");\n\t}\n\trecord_route();\n\tif (!lookup("location")) {'
    edit $'\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");' $'\tif (!lookup("location")) {\n\t\tt_newtran();\t# lesson 7.12: a transaction, so acc writes the refused call too\n\t\tsend_reply(404, "Not Found");'
    ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac
[[ $CASE == topohide || $CASE == ha || $CASE == transport || $CASE == ipv6 ]] || { cmp -s $PLAIN $CFG || diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff; }

tcpdump -i $CAPIF -U -s ${SNAP:-0} -w captures/$NAME.pcap "$CAPF" 2>/dev/null & TCPD=$!; sleep 1
OSIPS=
[ $DIRECT = 1 ] && { /usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2; }
RTPE=(rtpengine --config-file=none --interface=192.0.2.10 --listen-ng=127.0.0.1:2223 --listen-cli=127.0.0.1:9900
      --port-min=35000 --port-max=35099 --table=-1 --foreground --log-stderr --log-level=6 --pidfile=/tmp/rtpengine.pid)

case $CASE in
  topohide)
    # the call twice: the proxy (plain lab.cfg), then the SBC; the phones register again after each start (no db)
    SBC=$CFG; CFG=$PLAIN
    for run in proxy sbc; do
      [ $run = sbc ] && { CFG=$SBC
        iptables -t raw -I OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK
        echo "${RTPE[*]}" > captures/$NAME.rtpengine-cmdline.txt
        "${RTPE[@]}" > captures/$NAME.rtpengine.log 2>&1 & sleep 1; }
      /usr/sbin/opensips -F -f $CFG > captures/$NAME.$run.opensips.log 2>&1 & OSIPS=$!; sleep 2
      phone 2002 192.0.2.22 4402 40000 16 ";answermode=auto;answerdelay=1000"
      phone 2001 192.0.2.21 4401 30000 16; sleep 3
      ./bctl.py 4401 dial sip:2002@lab.sip >> captures/$NAME.ctl.log 2>&1; sleep 8
      ./bctl.py 4401 hangup >> captures/$NAME.ctl.log 2>&1; sleep 2
      mv captures/$NAME.2001.log captures/$NAME.$run.2001.log; mv captures/$NAME.2002.log captures/$NAME.$run.2002.log
      pkill -x baresip; sleep 1; kill $OSIPS; wait $OSIPS 2>/dev/null; sleep 1
    done
    diff $PLAIN $SBC > captures/$NAME.cfg.diff
    pkill -x rtpengine; iptables -t raw -D OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK 2>/dev/null
    OSIPS= ;;
  lb)
    # the back-ends: SIPp callees answering every call (180, 200, BYE from the caller) and every OPTIONS ping (-aa)
    for b in 31 32; do
      timeout 200 sipp -sf $S/answer.xml -s 8000 -i 192.0.2.$b -p 5060 -mp 6${b}0 -aa -nostdin -trace_msg \
        -message_file captures/$NAME.backend$b.msg.log > captures/$NAME.backend$b.log 2>&1 &
    done
    sipp_reg 2001 192.0.2.21; sleep 6
    CLI="opensips-cli -o fifo_file=$FIFO -x mi"
    CALLS="sipp lab.sip -sf scenarios/call.xml -s 2001 -au 2001 -ap lab-2001-pass -set callee 8000 -auth_uri 8000@lab.sip -i 192.0.2.21 -mp 30000 -r 1 -nostdin"
    INV="tshark -r /tmp/lb.pcap -Y 'sip.Method == \"INVITE\" && ip.src == 192.0.2.10' -T fields -e frame.time_relative -e ip.dst -e sip.Call-ID 2>/dev/null"
    term "sudo timeout 120 tcpdump -i lo -n -U -w /tmp/lb.pcap udp port 5060 > /dev/null 2>&1 &"; sleep 2
    term "$CLI dispatcher:list"
    term "$CALLS -m 4 > /dev/null; echo \"sipp exit code \$?\""
    term "$INV"
    note "# back-end 2 (192.0.2.32) dies: from now on nothing it is sent is answered"
    term "sudo iptables -I INPUT -d 192.0.2.32 -j DROP"
    term "$CALLS -m 4 > /dev/null; echo \"sipp exit code \$?\""
    term "$INV | tail -n +5"
    term "grep -E 'lb:|dispatcher:' captures/$NAME.opensips.log"
    term "$CLI dispatcher:list"
    term "sleep 10; $CLI dispatcher:list | grep -E 'URI|state'"
    term "$CALLS -m 2 > /dev/null; echo \"sipp exit code \$?\""
    term "$INV | tail -n 2"
    note "# back-end 2 is back"
    term "sudo iptables -D INPUT -d 192.0.2.32 -j DROP"
    term "sleep 12; $CLI dispatcher:list | grep -E 'URI|state'"
    term "grep 'dispatcher:' captures/$NAME.opensips.log"
    term "$CALLS -m 4 > /dev/null; echo \"sipp exit code \$?\""
    term "$INV | tail -n 4"
    iptables -D INPUT -d 192.0.2.32 -j DROP 2>/dev/null
    pkill -f "tcpdump -i lo -n -U -w /tmp/lb.pcap"; sleep 1
    cp /tmp/lb.pcap captures/$NAME.student.pcap; rm -f /tmp/lb.pcap ;;
  ha)
    tcpdump -i lo -U -s 0 -w captures/$NAME.lo.pcap 'udp' 2>/dev/null & TCPD2=$!
    ip netns exec nodea /usr/sbin/opensips -F -f /tmp/lab-nodea.cfg -P /run/opensips/nodea.pid > captures/$NAME.nodea.log 2>&1 &
    sleep 2
    ip netns exec nodeb /usr/sbin/opensips -F -f /tmp/lab-nodeb.cfg -P /run/opensips/nodeb.pid > captures/$NAME.nodeb.log 2>&1 &
    sleep 4
    CLIA="opensips-cli -o fifo_file=/run/opensips/nodea_fifo -x mi"; CLIB="opensips-cli -o fifo_file=/run/opensips/nodeb_fifo -x mi"
    term "$CLIB clusterer:list"
    term "$CLIB clusterer:list_shtags"
    phone 2002 192.0.2.22 4402 40000 80 ";answermode=auto;answerdelay=1000"
    phone 2001 192.0.2.21 4401 30000 80
    sipp_reg 2004 192.0.2.24
    timeout 60 sipp -sf $S/uas-ring.xml -s 2004 -i 192.0.2.24 -p 5060 -mp 6400 -m 1 -nostdin -trace_msg \
      -message_file captures/$NAME.2004.msg.log > captures/$NAME.2004.log 2>&1 &
    sleep 3
    note "# 2001, 2002 and 2004 registered through 192.0.2.10 (node A)"
    term "$CLIA usrloc:dump | grep -E '\"(AOR|Contact)\"'"
    term "$CLIB usrloc:dump | grep -E '\"(AOR|Contact)\"'"
    ./bctl.py 4401 dial sip:2002@lab.sip >> captures/$NAME.ctl.log 2>&1; sleep 4
    note "# 2001 called 2002 through node A (answered); 2003 calls 2004, which rings"
    timeout 40 sipp 192.0.2.10:5060 -sf $S/call-cancel.xml -s 2003 -au 2003 -ap lab-2003-pass -set callee 2004 \
      -auth_uri 2004@lab.sip -i 192.0.2.23 -p 5060 -mp 6300 -m 1 -d 12000 -nd -nostdin -trace_msg \
      -message_file captures/$NAME.2003.msg.log > captures/$NAME.2003.log 2>&1 & C3=$!
    sleep 2
    term "$CLIB dialog:list | grep -E '\"(callid|state|from_uri|to_uri|shtag)\"'"
    note "# node A dies (the take: kill -9 and its network link down)"
    pkill -9 -f /tmp/lab-nodea.cfg; ip -n nodea link set ha0 down
    note "# keepalived on node B (the take does it): 192.0.2.10 moves to node B, a gratuitous ARP, the sharing tag active"
    ip -n nodeb addr add 192.0.2.10/32 dev ha0; ip netns exec nodeb python3 /tmp/lab-garp.py ha0 192.0.2.10
    term "$CLIB clusterer:shtag_set_active vip/1"
    sleep 4
    term "$CLIB clusterer:list"
    term "$CLIB clusterer:list_shtags"
    sleep 3
    note "# 2003 gives up on the ringing call (CANCEL, 12 s after the 180); 2001 hangs up the call it made through node A"
    ./bctl.py 4401 hangup >> captures/$NAME.ctl.log 2>&1; sleep 8
    term "$CLIB dialog:list | grep -E '\"(callid|state|from_uri|to_uri|shtag)\"'"
    note "# a new call 2001 -> 2002, now through node B"
    ./bctl.py 4401 dial sip:2002@lab.sip >> captures/$NAME.ctl.log 2>&1; sleep 5
    term "$CLIB dialog:list | grep -E '\"(callid|state|from_uri|to_uri|shtag)\"'"
    ./bctl.py 4401 hangup >> captures/$NAME.ctl.log 2>&1; sleep 2
    term "grep -E 'node [ab]:|clusterer' captures/$NAME.nodeb.log"
    wait $C3 2>/dev/null
    pkill -f /tmp/lab-nodeb.cfg; sleep 2; kill $TCPD2 2>/dev/null
    for n in a b; do ip netns del node$n; done; ip link del habr
    iptables -D INPUT -i habr -j ACCEPT; ip addr add $LAB0 dev lab0
    rm -f /tmp/lab-garp.py /tmp/lab-node?.cfg /run/opensips/node?.pid ;;
  transport)
    tcpdump -i lo -U -s 0 -w captures/$NAME.hep.pcap 'udp port 9060' 2>/dev/null & TCPD2=$!
    python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("192.0.2.60",9060))
while True: s.recv(65535)' hep-sink & SINK=$!; echo $SINK > /tmp/lab-hep-sink.pid
    # the phones' DNS: in their namespaces the box's resolver (127.0.0.53) is out of reach; a lab dnsmasq on 192.0.2.53
    # answers lab.sip only (no upstream, no other name)
    addr 192.0.2.53
    /usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
      --listen-address=192.0.2.53 --port=53 --local=/sip/ --host-record=lab.sip,192.0.2.10 --log-queries --log-facility=- \
      > captures/$NAME.dnsmasq.log 2>&1 & DNSM=$!
    PHNS=1
    tcall() {  # tcall <label> <transport or ""> [account params]: both phones register over it, 2001 calls 2002
      local tag=$1; TRANSPORT=$2
      [[ -n ${RUNS:-} && " $RUNS " != *" $tag "* ]] && return   # RUNS="tls tcp-outbound": only those (when testing)
      phns_up; local secs=$(( ${WAIT:-3} + 20 ))
      phone 2002 192.0.2.22 4402 40000 $secs ";answermode=auto;answerdelay=1000${3:-}" "sip_cafile /tmp/lab-tls/ca.pem" "dns_server 192.0.2.53:53"
      phone 2001 192.0.2.21 4401 30000 $secs "${3:-}" "sip_cafile /tmp/lab-tls/ca.pem" "dns_server 192.0.2.53:53"; sleep ${WAIT:-3}
      echo "## $(date +%T) $tag: 2001 dials 2002" >> captures/$NAME.ctl.log
      bctl 4401 dial sip:2002@lab.sip; sleep 4
      { echo "## $(date +%T) $tag: the proxy's TCP/TLS connections during the call"
        ss -tn state established '( sport = :5060 or sport = :5061 or dport = :5060 or dport = :5061 )'; echo; } \
        >> captures/$NAME.conn.txt 2>&1
      sleep 2; bctl 4401 hangup; sleep 2
      phns_down
      for u in 2001 2002; do mv captures/$NAME.$u.log captures/$NAME.$tag.$u.log; done
      TRANSPORT=
    }
    /usr/sbin/opensips -F -f $CFG > captures/$NAME.plain.opensips.log 2>&1 & OSIPS=$!; sleep 2
    tcall udp ""; tcall tcp tcp; tcall tls tls
    kill $OSIPS; wait $OSIPS 2>/dev/null; sleep 1
    /usr/sbin/opensips -F -f $REUSE > captures/$NAME.reuse.opensips.log 2>&1 & OSIPS=$!; sleep 2
    tcall tls-reuse tls; tcall tcp-reuse tcp
    WAIT=40 tcall tcp-outbound tcp ';sipnat=outbound;outbound="sip:192.0.2.10;transport=tcp"'
    kill $OSIPS; wait $OSIPS 2>/dev/null; OSIPS=; kill $SINK $TCPD2 $DNSM; rm -f /tmp/lab-hep-sink.pid; PHNS=
    rm -rf /tmp/lab-tls ;;
  ipv6)
    # the IPv4 legs (proxy <-> 2003, rtpengine <-> 2003) stay on lo: a second capture, merged into the pcap at the end
    tcpdump -i lo -U -s 0 -w captures/$NAME.lo.pcap 'udp port 5060 or (udp portrange 35000-35099) or (udp portrange 50000-50009) or icmp' \
      2>/dev/null & TCPD2=$!
    PHNS=1
    v6phones() {  # v6phones <seconds>: 2001 and 2002 (IPv6-only, in their namespaces) and 2003 (IPv4-only, root)
      phns_up
      for u in 2001 2002; do
        local extra=';outbound="sip:[2001:db8::10]"'; [ $u = 2002 ] && extra+=';answermode=auto;answerdelay=1000'
        local n=2${u: -1}   # 2001 -> 21
        phone $u 2001:db8::$n 440${u: -1} $(( ${u: -1} + 2 ))0000 $1 "$extra" "sip_listen [2001:db8::$n]:5060" \
          "net_interface lab$n"
      done
      PHNS= phone 2003 192.0.2.23 4403 50000 $1 ";answermode=auto;answerdelay=1000"
    }
    v6call() {  # v6call <label> <callee>
      sleep 3; echo "## $(date +%T) $1: 2001 dials $2" >> captures/$NAME.ctl.log
      bctl 4401 dial sip:$2@lab.sip; sleep 7; bctl 4401 hangup; sleep 2
    }
    /usr/sbin/opensips -F -f $CFG > captures/$NAME.plain.opensips.log 2>&1 & OSIPS=$!; sleep 2
    v6phones 30; v6call v6-v6 2002; v6call v6-v4 2003
    phns_down; pkill -x baresip; sleep 1; for u in 2001 2002 2003; do mv captures/$NAME.$u.log captures/$NAME.plain.$u.log; done
    kill $OSIPS; wait $OSIPS 2>/dev/null; sleep 1
    iptables -t raw -I OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK
    RTPE=(rtpengine --config-file=none --interface=192.0.2.10 --interface=2001:db8::10 --listen-ng=127.0.0.1:2223
          --listen-cli=127.0.0.1:9900 --port-min=35000 --port-max=35099 --table=-1 --foreground --log-stderr --log-level=6
          --pidfile=/tmp/rtpengine.pid)
    echo "${RTPE[*]}" > captures/$NAME.rtpengine-cmdline.txt
    "${RTPE[@]}" > captures/$NAME.rtpengine.log 2>&1 & sleep 1
    /usr/sbin/opensips -F -f $BRIDGE > captures/$NAME.bridge.opensips.log 2>&1 & OSIPS=$!; sleep 2
    v6phones 20; v6call v6-v4-bridged 2003
    phns_down; pkill -x baresip; sleep 1; for u in 2001 2002 2003; do mv captures/$NAME.$u.log captures/$NAME.bridge.$u.log; done
    kill $OSIPS; wait $OSIPS 2>/dev/null; OSIPS=; pkill -x rtpengine; PHNS=; kill $TCPD2
    iptables -t raw -D OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK ;;
  ticket|ticketfix)
    for n in 1 2; do /usr/sbin/opensips -F -f /tmp/lab-sbc$n.cfg -P /run/opensips/sbc$n.pid > captures/$NAME.sbc$n.log 2>&1 & done
    sleep 2
    NOREG=1 phone 2002 192.0.2.22 4402 40000 60 ";answermode=auto;answerdelay=1000"
    NOREG=1 phone 2001 192.0.2.21 4401 30000 60 ';outbound="sip:192.0.2.10"'; sleep 3
    for c in 1 2 3 4; do
      echo "## $(date +%T) call $c: 2001 dials 2002" >> captures/$NAME.ctl.log
      bctl 4401 dial sip:2002@lab.sip; sleep 6; bctl 4401 hangup; sleep 3
    done
    sleep 2
    { echo "## the calls each SBC node still holds at the end (dialog:list): a dialog the BYE never reached stays"
      for n in 1 2; do echo "# sbc$n"; opensips-cli -o fifo_file=/run/opensips/sbc${n}_fifo -x mi dialog:list 2>&1 \
        | grep -E '"(callid|state|from_uri|to_uri)"'; done; } > captures/$NAME.mi.txt
    for n in 1 2; do pkill -f /tmp/lab-sbc$n.cfg; done; sleep 1
    for n in 1 2; do sed "s/@NAME@/sbc$n/g; s/@IP@/192.0.2.3$n/g" opensips/sbc-node.cfg | diff opensips/sbc-node.cfg - > captures/$NAME.sbc$n.cfg.diff; done
    rm -f /tmp/lab-sbc?.cfg ;;
  load)
    CLI="opensips-cli -o fifo_file=$FIFO -x mi"
    note "# the box: $(nproc) vCPU, $(free -m | awk '/^Mem:/ {print $2}') MB RAM; OpenSIPS 4.0.3 (lab.cfg, udp_workers=2), SIPp 3.7.3 on the same box"
    term "sipp lab.sip -sf scenarios/reg.xml -s 2002 -au 2002 -ap lab-2002-pass -auth_uri lab.sip -i 192.0.2.22 -m 1 -nostdin > /dev/null; echo \"register: sipp exit code \$?\""
    term "sipp -sn uas -i 192.0.2.22 -p 5060 -bg -nostdin -trace_stat -stf /tmp/uas-stat.csv -fd 1 -trace_screen -screen_file /tmp/uas.screen"
    sleep 1
    for r in 10 50 100 200 400; do
      term "sipp 192.0.2.10 -sf scenarios/load-plain-uac.xml -s 2002 -i 192.0.2.21 -p 5070 -r $r -m $((r * 10)) -l $((r * 4)) -d 2000 -recv_timeout 10000 -timeout 60s -nostdin -trace_screen -screen_file /tmp/uac-$r.screen -trace_stat -stf /tmp/uac-$r.csv -fd 1 > /dev/null; echo \"sipp exit code \$?\""
      term "sed -n '/Messages  Retrans/,/^-*\$/p;/Successful call/p;/Failed call/p;/Call Rate/p;/Response Time/p;/Call Length/p' /tmp/uac-$r.screen"
      term "for g in core: tm: shmem:; do $CLI statistics:get \$g; done | grep -E 'rcv_requests|fwd_requests|drop_requests|err_requests|UAS_transactions|inuse_transactions|[2-6]xx_transactions|used_size'"
      sleep 3
    done
    term "pkill -f 'sipp -sn uas'"
    term "tail -n 3 /tmp/uac-200.csv | cut -d';' -f1-3,9-20"
    for f in /tmp/uas.screen /tmp/uas-stat.csv /tmp/uac-*.screen /tmp/uac-*.csv; do
      b=$(basename "$f"); cp "$f" "captures/$NAME.${b}" 2>/dev/null; done
    rm -f /tmp/uas.screen /tmp/uas-stat.csv /tmp/uac-*.screen /tmp/uac-*.csv
    { echo "# SIP in the take's capture (tshark -z sip,stat), then INVITEs per second and how many were retransmissions"
      tshark -r captures/$NAME.pcap -q -z sip,stat 2>/dev/null
      echo "# second  INVITEs from SIPp  of them retransmitted (same branch seen before)"
      tshark -r captures/$NAME.pcap -Y 'sip.Method == "INVITE" && ip.src == 192.0.2.21' -T fields -e frame.time_relative \
        -e sip.Via.branch 2>/dev/null | awk '{s=int($1); n[s]++; if (seen[$2]++) r[s]++} END {for (k in n) print k, n[k], r[k]+0}' | sort -n
    } > captures/$NAME.stats.txt ;;
  hep)
    python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("192.0.2.60",9060))
while True: s.recv(65535)' hep-sink & SINK=$!; echo $SINK > /tmp/lab-hep-sink.pid
    phone 2002 192.0.2.22 4402 40000 50 ";answermode=auto;answerdelay=2000"
    phone 2001 192.0.2.21 4401 30000 50; sipp_reg 2004 192.0.2.24
    timeout 40 sipp -sf $S/uas-486.xml -s 2004 -i 192.0.2.24 -p 5060 -m 1 -nostdin > captures/$NAME.2004.log 2>&1 &
    sleep 3
    hcall() { echo "## $(date +%T) 2001 dials $1" >> captures/$NAME.ctl.log; bctl 4401 dial sip:$1@lab.sip; sleep $2; bctl 4401 hangup; sleep 2; }
    hcall 2002 9; hcall 2004 4; hcall 2009 3; hcall 2002 6
    sleep 2; kill $SINK; rm -f /tmp/lab-hep-sink.pid ;;
esac

sleep 1; for p in sipp baresip rtpengine; do pkill -x $p 2>/dev/null; done
kill $TCPD 2>/dev/null; sleep 1; [ -n "$OSIPS" ] && kill $OSIPS 2>/dev/null; sleep 1
[[ $CASE == transport || $CASE == ipv6 ]] && phbr_down
if [ $CASE = ipv6 ]; then   # one pcap: the bridge (IPv6 side) and lo (IPv4 side), in time order
  mergecap -F pcap -w captures/$NAME.merged.pcap captures/$NAME.pcap captures/$NAME.lo.pcap \
    && mv captures/$NAME.merged.pcap captures/$NAME.pcap && rm -f captures/$NAME.lo.pcap
fi
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
rm -rf /tmp/lab-scale
R="-o rtp.heuristic_rtp:TRUE"
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap $R -Y "rtp or rtpevent or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
if [ $CASE = ipv6 ]; then   # IPv6 is beyond pcap_messages.py
  python3 /tmp/lab-decode.py sip captures/$NAME.pcap captures/$NAME.messages.txt >/dev/null
  tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ipv6.src -e ip.dst \
    -e ipv6.dst -e _ws.col.Info 2>/dev/null > captures/$NAME.txt
  tshark -r captures/$NAME.pcap $R -Y "rtp or icmp or icmpv6" -T fields -e frame.number -e frame.time_relative -e ip.src \
    -e ipv6.src -e udp.srcport -e ip.dst -e ipv6.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
elif [ $CASE = hep ]; then   # the HEP packets are in the same capture (lo), next to the SIP they copy
  python3 pcap_messages.py captures/$NAME.pcap >/dev/null
  python3 /tmp/lab-decode.py hep captures/$NAME.pcap captures/$NAME.hep.txt >/dev/null
  { echo "# acc CDRs (db_flatstore, /tmp/lab-acc/acc_<process>.log, joined and sorted by time); answered calls (cdr) and refused"
    echo "# ones (failed) share the columns: method|from_tag|to_tag|callid|sip_code|sip_reason|time|caller|callee|src_ip|user_agent|setuptime|created|duration|ms_duration"
    cat /tmp/lab-acc/acc_*.log 2>/dev/null | sort -t'|' -k7,7n; } > captures/$NAME.cdr.txt
  rm -rf /tmp/lab-acc
elif [ $CASE = transport ]; then   # TCP and TLS are beyond pcap_messages.py; the TLS legs are read from the HEP mirror
  python3 /tmp/lab-decode.py sip captures/$NAME.pcap captures/$NAME.messages.txt >/dev/null
  python3 /tmp/lab-decode.py hep captures/$NAME.hep.pcap captures/$NAME.hep.txt >/dev/null
  tshark -r captures/$NAME.pcap -Y "sip or tls or tcp.flags.syn == 1 or tcp.flags.fin == 1" -T fields -e frame.number \
    -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null \
    | grep -v -P '\t9060\t' > captures/$NAME.txt
else
[ $CASE = load ] || python3 pcap_messages.py captures/$NAME.pcap >/dev/null
fi
if [ $CASE = ha ]; then   # the media went phone to phone on lo; the bridge capture has the ARP and the node-to-node BIN link
  tshark -r captures/$NAME.lo.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
  tshark -r captures/$NAME.lo.pcap $R -Y rtp -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport \
    -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
  tshark -r captures/$NAME.pcap -Y arp -T fields -e frame.number -e frame.time_relative -e eth.src -e _ws.col.Info \
    2>/dev/null > captures/$NAME.arp.txt
  tshark -r captures/$NAME.pcap -Y "tcp.port == 5566" -T fields -e frame.number -e frame.time_relative -e ip.src \
    -e ip.dst -e tcp.len -e _ws.col.Info 2>/dev/null > captures/$NAME.bin.txt
fi
# mask every eth0/eth1 IPv4 (the droplet's public and private addresses) in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.*diff 2>/dev/null
done
rm -f /tmp/lab-decode.py /tmp/lab-check.txt /tmp/lab-take-reuse.cfg /tmp/lab-take-bridge.cfg
chown -R lab:lab captures
cat captures/$NAME.txt
