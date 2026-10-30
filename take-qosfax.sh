#!/bin/bash
# sip-lab takes for section 6 part B (voice on real networks: QoS marking, comfort noise and silence suppression, fax
# over IP). Same plumbing as take-callctl.sh. Everything is on one box: there is no router or switch between the
# elements, so these takes show how each element MARKS its packets, never where queues form or what a network does
# with the marks. There is no fax machine either: the fax gateways are SIPp scenarios that play generated tones and
# T.38 packets (scenarios/make_qosfax_media.py).
#   sudo ./take-qosfax.sh <case> <name>
# Cases (lesson):
#   dscp dscppj (6.9)          DS field of SIP and RTP: OpenSIPS marks the SIP it sends (core parameter tos), baresip
#                              marks RTP with rtp_tos (2001 keeps baresip's default 184 = EF, 2002 is set to 0 =
#                              unmarked); dscppj: two pjsua phones, 2001 with --set-qos, 2002 without
#   cng novad cn (6.10)        pjsua 2002 answers and plays talk-silence.wav (1 s tone, 3 s silence) with VAD on (cng,
#                              pjsua's default for PCMU) or off (novad, --no-vad); pjsua 2001 calls with --no-vad.
#                              pjsua sends no CN (it does not offer payload 13): cn = rtpengine on the proxy
#                              transcodes the call (pjsua 2002, PCMU, no VAD, plays talk-silence.wav; SIPp 2001 offers
#                              PCMA + CN and only listens) with --silence-detect, so it replaces the silent frames it
#                              sends to 2001 with RFC 3389 CN packets (--cn-payload: noise level 60 = -60 dBov)
#   passthru t38 (6.11)        fax gateways (SIPp): G.711 pass-through; the T.38 re-INVITE answered 200
#   t38fail faxg729 (6.12)     the T.38 re-INVITE answered 488 (the call stays in G.711); a call offered G.729 only
#   ticket ticketfix (6.13)    "faxes never start": 488 to T.38 and the receiving gateway hangs up; fix: the far end
#                              accepts T.38
# Phones: 2001 = 192.0.2.21 (caller, emitting fax gateway), 2002 = 192.0.2.22 (callee, receiving fax gateway).
# Writes captures/<name>.pcap (SIP + RTP + UDPTL + ICMP on lo), .txt (SIP summary), .messages.txt (pcap_messages.py),
# .rtp.txt (RTP streams), .media.txt, .dscp.txt (dscp cases), .gaps.txt (every RTP stream's gaps), .t38.txt (fax
# cases: the UDPTL packets decoded), the logs of every element and .cfg.diff when lab.cfg changes. Leaves nothing
# running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x pjsua 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
mkdir -p /run/opensips
S=scenarios
B1=4401; B2=4402
rm -f captures/$NAME.*
[ -f $S/fax-t38.pcap ] && [ -f $S/fax-silence.pcap ] && [ -f $S/talk-silence.wav ] || (cd $S && python3 make_qosfax_media.py >/dev/null)

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
case $CASE in
  # the proxy marks every packet it sends with DSCP CS5 (101000 = 40; TOS byte 40 << 2 = 0xA0), the Signaling class
  # of RFC 4594 4.2 / table 3 ("IP Telephony signaling")
  dscp|dscppj) edit $'auto_aliases=no\n' $'auto_aliases=no\n# lesson 6.9: DSCP CS5 (RFC 4594 Signaling class) on every packet OpenSIPS sends: TOS byte = DSCP << 2\ntos=0xA0\n' ;;
  # the call's media through rtpengine, which transcodes PCMU (2002) <-> PCMA (2001): the offer to 2002 hides PCMA and
  # adds PCMU (codec-mask-PCMA codec-accept-CN transcode-PCMU); CN stays in that offer (m=audio ... 0 13) and 2002
  # answers PCMU only, while 2001 keeps the PCMA and CN it offered, both handled by rtpengine
  cn) edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# lesson 6.10: media relay and transcoder\nloadmodule "rtpengine.so"\nmodparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")\n'
      edit $'\t\tif (loose_route()) {\n' $'\t\tif (is_method("BYE"))\n\t\t\trtpengine_delete();\t# the call is over: free the relay ports\n\t\tif (loose_route()) {\n'
      edit $'\tt_relay();\n}\n\n# the lab' $'\t# lesson 6.10: the media goes through rtpengine, which transcodes: 2002 sees PCMU only, 2001 keeps PCMA\n\tif (is_method("INVITE") && has_body("application/sdp")) {\n\t\trtpengine_offer("replace-origin codec-mask-PCMA codec-accept-CN transcode-PCMU");\n\t\tt_on_reply("relay");\n\t}\n\tt_relay();\n}\n\n# lesson 6.10: the answer through rtpengine too\nonreply_route[relay] {\n\tif (has_body("application/sdp"))\n\t\trtpengine_answer("replace-origin");\n}\n\n# the lab' ;;
esac
cmp -s $PLAIN $CFG || diff $PLAIN $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

RTPE=(rtpengine --config-file=none --interface=192.0.2.10 --listen-ng=127.0.0.1:2223 --listen-cli=127.0.0.1:9900
      --port-min=35000 --port-max=35099 --table=-1 --foreground --log-stderr --log-level=6 --pidfile=/tmp/rtpengine.pid
      --silence-detect=0.01 --cn-payload=60)
if [ $CASE = cn ]; then
  # rtpengine's own socket is bound to 192.0.2.10: leave it untracked, as SIPp's (net.sh explains why)
  iptables -t raw -I OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK
  echo "${RTPE[*]}" > captures/$NAME.rtpengine-cmdline.txt
  "${RTPE[@]}" > captures/$NAME.rtpengine.log 2>&1 & sleep 1   # before OpenSIPS: it pings rtpengine at start
fi
/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] [rtp_tos]
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" "${6:-}")
  [ -n "${7:-}" ] && sed -i "s|^rtp_tos.*|rtp_tos\t\t\t$7|" "$d/config"
  grep "^rtp_tos" "$d/config" | sed "s/^/$1: /" >> captures/$NAME.ctl.log
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
HOLDERS=()
# pjsua phone (as take-callctl.sh): no sound card, PCMU only, UDP only, no session timer; VAD and QoS per case
PJSUA_COMMON=(--null-audio --no-tcp --local-port 5060 --dis-codec "" --add-codec PCMU --use-timer 0
              --log-level 4 --app-log-level 3)
pjphone() {  # pjphone <user> <ip> <rtp-port> <seconds> [pjsua options]
  local u=$1 ip=$2 rtp=$3 secs=$4 fifo=/tmp/pjsua-$1.in; shift 4
  rm -f "$fifo"; mkfifo "$fifo"
  sleep "$secs" > "$fifo" & HOLDERS+=($!)
  timeout "$secs" stdbuf -oL pjsua --id "sip:$u@lab.sip" --registrar sip:lab.sip --realm lab.sip --username "$u" \
    --password "lab-$u-pass" --ip-addr "$ip" --bound-addr "$ip" --rtp-port "$rtp" "${PJSUA_COMMON[@]}" \
    --log-file "captures/$NAME.$u.log" "$@" < "$fifo" > "captures/$NAME.$u.console.log" 2>&1 &
}
pj() {  # pj <delay> <user> <line> [line ...]: wait, then type these lines into that pjsua console
  sleep "$1"; local u=$2; shift 2
  timeout 2 bash -c 'printf "%s\n" "${@:2}" > "$1"' _ "/tmp/pjsua-$u.in" "$@" || echo "pj: $u is not running"
  echo "$(date +%T.%3N) $u: $*" >> captures/$NAME.ctl.log
}
sink() {  # sink <ip> <port> <seconds>: a socket that takes the RTP (port) and RTCP (port + 1) a SIPp phone does not read
  timeout "$3" python3 -c 'import socket, sys, select
ss = []
for port in (int(sys.argv[2]), int(sys.argv[2]) + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], port)); ss.append(s)
while True:
    for s in select.select(ss, [], [])[0]:
        s.recv(4096)' "$1" "$2" &
}
fax() {  # fax <callee mode> <caller answer> [seconds]: SIPp gateways 2002 (receiving) and 2001 (emitting)
  sink 192.0.2.21 30000 "${3:-30}"; sink 192.0.2.22 40000 "${3:-30}"   # SIPp plays media but does not read it
  sipp_reg 2002 192.0.2.22
  timeout "${3:-30}" sipp -sf $S/fax-callee.xml -s 2002 -set mode "$1" -i 192.0.2.22 -p 5060 -mi 192.0.2.22 \
    -min_rtp_port 40000 -max_rtp_port 40009 -m 1 -timeout "${3:-30}s" -nostdin -trace_msg \
    -message_file captures/$NAME.2002.msg.log > captures/$NAME.2002.log 2>&1 &
  sleep 1
  timeout "${3:-30}" sipp 192.0.2.10:5060 -sf $S/fax-caller.xml -s 2001 -set callee 2002 -set answer "$2" \
    -auth_uri 2002@lab.sip -au 2001 -ap lab-2001-pass -i 192.0.2.21 -p 5060 -mi 192.0.2.21 \
    -min_rtp_port 30000 -max_rtp_port 30009 -m 1 -timeout "${3:-30}s" -nostdin -trace_msg \
    -message_file captures/$NAME.2001.msg.log > captures/$NAME.2001.log 2>&1 || echo "caller sipp ended with an error"
  sleep 2
}

case $CASE in
  # baresip 2001 (rtp_tos 184 = EF, baresip's default) calls baresip 2002 (rtp_tos 0); 8 s of call, 2001 hangs up
  dscp)     phone 2002 192.0.2.22 $B2 40000 20 ";answermode=auto;answerdelay=1000" 0
            phone 2001 192.0.2.21 $B1 30000 20; sleep 3
            ctl 0 $B1 dial sip:2002@lab.sip; ctl 9 $B1 hangup; sleep 2 ;;
  # pjsua 2001 with --set-qos calls pjsua 2002 without it; 8 s of call
  dscppj)   pjphone 2002 192.0.2.22 40000 20 --no-vad --auto-answer 200
            pjphone 2001 192.0.2.21 30000 20 --no-vad --set-qos; sleep 3
            pj 0 2001 m sip:2002@lab.sip; pj 9 2001 h; sleep 2 ;;
  # pjsua 2002 answers and plays talk-silence.wav (looped) with VAD on (cng) or off (novad); pjsua 2001 sends
  # null-audio silence with VAD off; 17 s of call (four talk/silence cycles), 2001 hangs up
  cng|novad) VAD=(); [ $CASE = novad ] && VAD=(--no-vad)
            pjphone 2002 192.0.2.22 40000 30 "${VAD[@]}" --auto-answer 200 --play-file $S/talk-silence.wav --auto-play
            pjphone 2001 192.0.2.21 30000 30 --no-vad; sleep 3
            pj 0 2001 m sip:2002@lab.sip; pj 18 2001 h; sleep 2 ;;
  # rtpengine in the middle: pjsua 2002 (no VAD, PCMU) plays talk-silence.wav to SIPp 2001 (PCMA + CN, listens)
  cn)       pjphone 2002 192.0.2.22 40000 30 --no-vad --auto-answer 200 --play-file $S/talk-silence.wav --auto-play
            sink 192.0.2.21 30000 28; sleep 2
            timeout 28 sipp 192.0.2.10:5060 -sf $S/call-cn.xml -s 2001 -set callee 2002 -auth_uri 2002@lab.sip \
              -au 2001 -ap lab-2001-pass -i 192.0.2.21 -p 5060 -mi 192.0.2.21 -min_rtp_port 30000 \
              -max_rtp_port 30009 -m 1 -timeout 28s -nostdin > captures/$NAME.2001.log 2>&1 || echo "sipp error"
            sleep 1 ;;
  passthru) fax passthru none ;;
  t38|ticketfix) fax t38 t38 ;;
  t38fail)  fax stay refuse ;;
  ticket)   fax giveup refuse ;;
  # a call offered G.729 only (no RTP is sent: the take is the SDP); the far end is a G.729-only trunk
  faxg729)  sipp_reg 2002 192.0.2.22
            timeout 20 sipp -sf $S/uas-g729only.xml -s 2002 -i 192.0.2.22 -p 5060 -mi 192.0.2.22 \
              -min_rtp_port 40000 -max_rtp_port 40009 -m 1 -timeout 20s -nostdin > captures/$NAME.2002.log 2>&1 &
            sleep 1
            timeout 20 sipp 192.0.2.10:5060 -sf $S/call-g729.xml -s 2001 -set callee 2002 -auth_uri 2002@lab.sip \
              -au 2001 -ap lab-2001-pass -i 192.0.2.21 -p 5060 -mi 192.0.2.21 -min_rtp_port 30000 \
              -max_rtp_port 30009 -m 1 -timeout 20s -nostdin > captures/$NAME.2001.log 2>&1 || echo "sipp error"
            sleep 2 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x pjsua 2>/dev/null
if [ $CASE = cn ]; then
  pkill -x rtpengine 2>/dev/null; iptables -t raw -D OUTPUT -p udp -s 192.0.2.10 --sport 35000:35099 -j NOTRACK
fi
for p in "${HOLDERS[@]}"; do kill "$p" 2>/dev/null; done; rm -f /tmp/pjsua-*.in
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
R="-o rtp.heuristic_rtp:TRUE"
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap $R -Y "rtp or icmp or t38" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
# every RTP stream: packets, payload types, and each gap over 30 ms between two packets (time, seq, marker bit)
tshark -r captures/$NAME.pcap $R -Y "rtp and not icmp" -T fields -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst \
  -e udp.dstport -e rtp.seq -e rtp.timestamp -e rtp.marker -e rtp.p_type -e rtp.payload 2>/dev/null | python3 -c '
import sys, collections
streams = collections.OrderedDict()
for line in sys.stdin:
    t, s, sp, d, dp, seq, ts, m, pt, pl = line.rstrip("\n").split("\t")
    streams.setdefault(f"{s}:{sp} -> {d}:{dp}", []).append((float(t), int(seq), m, pt, int(ts), pl.replace(":", "")))
print("# each RTP stream: packets, payload types, and every gap over 30 ms between two packets in a row")
print("# (time of the packet after the gap, gap length, sequence numbers and RTP timestamps before/after, marker bit and")
print("# payload type of the packet after the gap), and every change of payload type (a CN packet, payload type 13,")
print("# carries the noise level in -dBov in its first octet, RFC 3389 section 3)")
for k, pk in streams.items():
    pts = collections.Counter(p[3] for p in pk)
    print(f"\n{k}  {len(pk)} packets  {pk[0][0]:.3f}-{pk[-1][0]:.3f} s  payload types " +
          ", ".join(f"{a}: {b}" for a, b in sorted(pts.items())))
    for a, b in zip(pk, pk[1:]):
        if b[3] != a[3]:
            cn = f"  CN payload {b[5]} (noise level -{int(b[5][:2], 16)} dBov)" if b[3] == "13" and b[5] else ""
            print(f"  {b[0]:7.3f} s  payload type {a[3]} -> {b[3]}  seq {a[1]} -> {b[1]}  marker {b[2]}{cn}")
        if b[0] - a[0] > 0.030:
            print(f"  {b[0]:7.3f} s  gap {1000 * (b[0] - a[0]):6.0f} ms  seq {a[1]} -> {b[1]}  ts {a[4]} -> {b[4]}"
                  f" (+{b[4] - a[4]})  marker {b[2]}  pt {b[3]}")
' > captures/$NAME.gaps.txt
case $CASE in
  dscp|dscppj)  # the DS field of every packet, and a summary per flow
    tshark -r captures/$NAME.pcap $R -Y "(sip or rtp or rtcp) and not icmp" -T fields -e frame.number -e frame.time_relative \
      -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e ip.dsfield -e ip.dsfield.dscp -e _ws.col.Protocol \
      -e _ws.col.Info 2>/dev/null | python3 -c '
import sys, collections
NAMES = {0: "CS0 (default)", 8: "CS1", 16: "CS2", 24: "CS3", 26: "AF31", 32: "CS4", 34: "AF41", 40: "CS5", 46: "EF",
         48: "CS6", 56: "CS7"}
rows, flows = [], collections.OrderedDict()
for line in sys.stdin:
    n, t, s, sp, d, dp, ds, dscp, proto, info = line.rstrip("\n").split("\t", 9)
    dscp = int(dscp); name = NAMES.get(dscp, str(dscp))
    rows.append(f"{n:>5} {float(t):8.3f}  {s}:{sp} -> {d}:{dp}  {proto:5} DS {ds} DSCP {dscp:2} {name:13} {info[:60]}")
    key = (f"{s}:{sp} -> {d}:{dp}", proto if proto in ("RTP", "RTCP") else "SIP")
    flows.setdefault(key, collections.Counter())[f"{dscp} {name}"] += 1
print("# per flow: packets by DSCP (the 6 high bits of the IPv4 DS field, RFC 2474)")
for (f, p), c in flows.items():
    print(f"{p:4}  {f:40}  " + ", ".join(f"DSCP {k}: {v}" for k, v in c.items()))
print("\n# every packet: frame, time, flow, protocol, DS field byte, DSCP, class name, summary")
print("\n".join(rows))' > captures/$NAME.dscp.txt ;;
  passthru|t38|t38fail|ticket|ticketfix)  # the T.38 packets as Wireshark decodes them
    tshark -r captures/$NAME.pcap -Y t38 -V 2>/dev/null | grep -E "^Frame|Internet Protocol|User Datagram|seq-number|t30-indicator|t30-data|field-type|error-recovery|secondary-ifp|primary-ifp|^ITU-T" \
      > captures/$NAME.t38.txt ;;
esac
python3 pcap_messages.py captures/$NAME.pcap >/dev/null
# pjsua and baresip may log the droplet's public address: mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
grep -v -E "REGISTER|401 Unauth" captures/$NAME.txt
echo "=== rtp ==="; cat captures/$NAME.rtp.txt
