#!/bin/bash
# sip-lab takes for section 5 part A (call control: hold, music on hold, REFER, transfers), the flows of RFC 5359 2.1-2.5
# and RFC 5589 played on the lab. Same plumbing as take-errors.sh. Roles: baresip phones where baresip 1.1.0 can do it
# (hold, resume, consultation call, blind transfer by REFER, following a REFER); pjsua 2.17 phones (pjproject's console
# phone, /usr/local/bin/pjsua, built by cloud-init) for what baresip cannot: attended transfer with Replaces, Referred-By,
# Refer-Sub: false, a transferor that takes the transferee back after a failed transfer, and the music server that
# follows a REFER (RFC 5359 2.3). SIPp only for an old phone's 0.0.0.0 hold and the busy target of xferfail-baresip.
# A pjsua phone is one process at its own 192.0.2.x address, driven through its console: the take writes the keys a
# person would type (m = call, H = hold, v = re-INVITE off hold, x = transfer, X = transfer with Replaces, h = hang up,
# [ ] = previous/next call) into a FIFO that is the phone's stdin, and logs every key it sends in <name>.ctl.log.
#   sudo ./take-callctl.sh <case> <name>
# Cases: hold holdlegacy consult moh refer norefersub norefersub-baresip blind attended referredby referredby-baresip
#        xferfail xferfail-baresip xfernoanswer ticket ticketfix
# Phones: 2001 = 192.0.2.21 (the transferee), 2002 = 192.0.2.22 (the transferor, the one who holds), 2003 = 192.0.2.23
# (the transfer target); the music server = 192.0.2.30 (pjsua, added to lab0 for the take).
# Writes captures/<name>.pcap (SIP + RTP + ICMP on lo), .txt (SIP summary), .rtp.txt (RTP streams), .media.txt, the logs
# of every element and .cfg.diff when lab.cfg changes. Leaves nothing running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x pjsua 2>/dev/null; sleep 1
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
LOOKUP=$'\tif (!lookup("location")) {\n'
case $CASE in
  # the music server is not a registered phone: the proxy sends sip:music@lab.sip to its address
  moh) edit "$LOOKUP" $'\t# lesson 5.2: the music-on-hold server (a media server, not a registered phone)\n\tif ($rU == "music") {\n\t\t$du = "sip:192.0.2.30:5060";\n\t\tt_relay();\n\t\texit;\n\t}\n'"$LOOKUP"
       addr 192.0.2.30 ;;
esac
cmp -s $PLAIN $CFG || diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1

declare -A NAMES=()   # display names (caller ID) for the phones of a take: NAMES[2001]=Alice
phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params]
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" "${6:-}")
  [ -n "${NAMES[$1]:-}" ] && sed -i "s|^<sip:|\"${NAMES[$1]}\" <sip:|" "$d/accounts"
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
HOLDERS=()   # the processes that keep each pjsua console's FIFO open
# pjsua phone: no sound card (--null-audio: it sends silence, so RTP flows), PCMU only, UDP only, no session timer and
# no VAD (fewer lines on the boards); its log (level 4: every SIP message in full) goes to captures/<name>.<tag>.log,
# what its screen shows (menus, "Current call id=0 to ...", transfer prompts) to captures/<name>.<tag>.console.log
PJSUA_COMMON=(--null-audio --no-tcp --local-port 5060 --dis-codec "" --add-codec PCMU --use-timer 0 --no-vad
              --log-level 4 --app-log-level 3)
pjphone() {  # pjphone <user|music> <ip> <rtp-port> <seconds> [pjsua options]
  local u=$1 ip=$2 rtp=$3 secs=$4 fifo=/tmp/pjsua-$1.in id; shift 4
  local acct=()
  if [ "$u" = music ]; then
    acct=(--id "sip:music@$ip")   # a server: no registration; lab.cfg sends sip:music@lab.sip to its address
  else
    id="sip:$u@lab.sip"; [ -n "${NAMES[$u]:-}" ] && id="\"${NAMES[$u]}\" <sip:$u@lab.sip>"
    acct=(--id "$id" --registrar sip:lab.sip --realm lab.sip --username "$u" --password "lab-$u-pass")
  fi
  rm -f "$fifo"; mkfifo "$fifo"
  sleep "$secs" > "$fifo" & HOLDERS+=($!)
  timeout "$secs" stdbuf -oL pjsua "${acct[@]}" --ip-addr "$ip" --bound-addr "$ip" --rtp-port "$rtp" "${PJSUA_COMMON[@]}" \
    --log-file "captures/$NAME.$u.log" "$@" < "$fifo" > "captures/$NAME.$u.console.log" 2>&1 &
}
pj() {  # pj <delay> <user> <line> [line ...]: wait, then type these lines into that pjsua console
  sleep "$1"; local u=$2; shift 2
  timeout 2 bash -c 'printf "%s\n" "${@:2}" > "$1"' _ "/tmp/pjsua-$u.in" "$@" || echo "pj: $u is not running"
  echo "$(date +%T.%3N) $u: $*" >> captures/$NAME.ctl.log
}
# a dialog's ids from the capture so far: the 200 OK to the INVITE that <ip> answered (Call-ID, From tag, To tag)
dialog_ids() {
  tshark -r captures/$NAME.pcap -Y "sip.Status-Code == 200 && sip.CSeq.method == \"INVITE\" && ip.src == $1" \
    -T fields -e sip.Call-ID -e sip.from.tag -e sip.to.tag 2>/dev/null | head -1
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
AUTO=";answermode=auto;answerdelay=1000"

case $CASE in
  # RFC 5359 2.1 on two baresip phones: 2001 calls 2002; 2002 holds (a=sendonly, answered recvonly); 2001 holds too
  # (a=sendonly offered, answered inactive); 2001 resumes (2002 still holds); 2002 resumes; 2001 hangs up
  hold)     phone 2002 192.0.2.22 $B2 40000 32 "$AUTO"; phone 2001 192.0.2.21 $B1 30000 32; sleep 3
            ctl 0 $B1 dial sip:2002@lab.sip; ctl 5 $B2 hold; ctl 5 $B1 hold; ctl 5 $B1 resume; ctl 5 $B2 resume
            ctl 4 $B1 hangup; sleep 2 ;;
  # an old phone's hold (RFC 2543): SIPp 2003 calls baresip 2002, re-INVITEs with c=0.0.0.0, then back, then BYE
  holdlegacy)
            phone 2002 192.0.2.22 $B2 40000 30 "$AUTO"; sleep 3; sipp_reg 2003 192.0.2.23
            timeout 28 sipp 192.0.2.10:5060 -sf $S/call-hold-legacy.xml -s 2003 -set callee 2002 -auth_uri 2002@lab.sip \
              -au 2003 -ap lab-2003-pass -i 192.0.2.23 -p 5060 -min_rtp_port 50000 -max_rtp_port 50009 -m 1 -timeout 28s \
              -nostdin > captures/$NAME.sipp.log 2>&1 || echo "sipp ended with an error"
            sleep 1 ;;
  # RFC 5359 2.2 consultation hold: 2001 calls 2002; 2002 holds 2001, calls 2003, hangs up 2003, takes 2001 back
  consult)  phone 2002 192.0.2.22 $B2 40000 36 "$AUTO"; phone 2003 192.0.2.23 $B3 50000 36 "$AUTO"
            phone 2001 192.0.2.21 $B1 30000 36; sleep 3
            ctl 0 $B1 dial sip:2002@lab.sip; ctl 5 $B2 hold; ctl 2 $B2 dial sip:2003@lab.sip; ctl 7 $B2 hangup
            ctl 2 $B2 line 1; ctl 0 $B2 resume; ctl 5 $B1 hangup; sleep 2 ;;
  # RFC 5359 2.3 music on hold, pjsua phones: Alice 2001 calls Bob 2002; Bob holds Alice, calls the music server
  # (pjsua at 192.0.2.30 that answers every call and plays voice-pcmu.wav) and transfers with Replaces (X): a REFER to
  # the music server with Refer-To: <sip:2001@lab.sip?Replaces=<Alice-Bob dialog>>; the music server's INVITE with
  # Replaces reaches Alice, she BYEs Bob and hears the music; NOTIFY 200 to Bob, who hangs up the music server's call.
  # Differs from the RFC: Bob's REFER goes inside a call he makes to the music server (pjsua sends no REFER outside a
  # dialog), and Bob cannot take Alice back (F19, an INVITE with Replaces naming the music dialog: pjsua's console takes
  # a URI of at most 127 characters); Alice hangs up the music at the end
  moh)      pjphone music 192.0.2.30 6000 40 --auto-answer 200 --play-file scenarios/voice-pcmu.wav --auto-play
            pjphone 2002 192.0.2.22 40000 40 --auto-answer 200; pjphone 2001 192.0.2.21 30000 40; sleep 3
            pj 0 2001 m sip:2002@lab.sip; pj 4 2002 H; pj 3 2002 m sip:music@lab.sip; pj 3 2002 X 0
            pj 14 2001 h; sleep 2 ;;
  # REFER on three baresip phones: 2001 calls 2002; 2002 transfers it to 2003 (REFER, 202, NOTIFY 100, NOTIFY 200)
  refer)    phone 2002 192.0.2.22 $B2 40000 30 "$AUTO"; phone 2003 192.0.2.23 $B3 50000 30 "$AUTO"
            phone 2001 192.0.2.21 $B1 30000 30; sleep 3
            ctl 0 $B1 dial sip:2002@lab.sip; ctl 5 $B2 transfer sip:2003@lab.sip; ctl 8 $B3 hangup; sleep 2 ;;
  # RFC 4488: pjsua 2002 started with --norefersub holds 2001 and transfers it (x) to pjsua 2003: REFER with
  # Refer-Sub: false. norefersub: the transferee is pjsua 2001 (Supported: norefersub): 202 with Refer-Sub: false, no
  # NOTIFY, and 2002 hangs up at once (pjsua takes that 202 as the transfer's success). norefersub-baresip: the same
  # REFER to baresip 2001, which ignores it: 202 without Refer-Sub and NOTIFYs as usual; 2002 hangs up on the NOTIFY 200
  norefersub|norefersub-baresip)
            pjphone 2003 192.0.2.23 50000 30 --auto-answer 200
            pjphone 2002 192.0.2.22 40000 30 --auto-answer 200 --norefersub
            if [ $CASE = norefersub ]; then pjphone 2001 192.0.2.21 30000 30; sleep 3; pj 0 2001 m sip:2002@lab.sip
            else phone 2001 192.0.2.21 $B1 30000 30; sleep 3; ctl 0 $B1 dial sip:2002@lab.sip; fi
            pj 4 2002 H; pj 3 2002 x sip:2003@lab.sip; pj 8 2003 h; sleep 3 ;;
  # RFC 5589 6.1 (6.2: REFER in the dialog) on three baresip phones: 2002 holds 2001, REFERs it to 2003, hangs up on the
  # NOTIFY 200; 2003 (the target) hangs up at the end
  blind)    phone 2002 192.0.2.22 $B2 40000 30 "$AUTO"; phone 2003 192.0.2.23 $B3 50000 30 "$AUTO"
            phone 2001 192.0.2.21 $B1 30000 30; sleep 3
            ctl 0 $B1 dial sip:2002@lab.sip; ctl 4 $B2 hold; ctl 3 $B2 transfer sip:2003@lab.sip; ctl 8 $B3 hangup; sleep 2 ;;
  # RFC 5589 7.3 attended transfer, three pjsua phones: 2001 calls 2002; 2002 holds 2001 (H), calls 2003 (m), holds
  # 2003 (H), goes back to the first call ([) and transfers it replacing the second (X 1): REFER to 2001 with Refer-To:
  # <sip:2003@lab.sip?Replaces=<2002-2003 call-id>;to-tag=<2003's tag>;from-tag=<2002's tag>> (escaped); 2001's INVITE
  # with Replaces and Referred-By; 2003 answers it and BYEs the 2002-2003 dialog; NOTIFY 200; 2002 BYEs 2001; 2003 hangs
  # up at the end
  attended) pjphone 2003 192.0.2.23 50000 30 --auto-answer 200; pjphone 2002 192.0.2.22 40000 30 --auto-answer 200
            pjphone 2001 192.0.2.21 30000 30; sleep 3
            pj 0 2001 m sip:2002@lab.sip; pj 4 2002 H; pj 2 2002 m sip:2003@lab.sip; pj 4 2002 H; pj 2 2002 "[" X 1
            pj 8 2003 h; sleep 2 ;;
  # 5.8's ticket: the transferor builds the Replaces with the tags the wrong way round. pjsua's X always builds it
  # right and its x takes at most 127 characters (the Refer-To needs about 150), so the transferor here is baresip 2002
  # (auto answer), whose transfer command sends any Refer-To it is given: it holds 2001, calls pjsua 2003, holds it,
  # goes back to line 1 and transfers with the Refer-To the take builds from the 200 OK 2003 sent (ticket: to-tag =
  # 2002's tag, from-tag = 2003's; ticketfix: the right way). ticket: 2003 answers 481, NOTIFY 481, baresip hangs up on
  # 2001 anyway and the 2002-2003 dialog (both on hold) never gets a BYE. ticketfix: 2003 replaces the dialog (BYE to
  # 2002), NOTIFY 200, 2002 BYEs 2001, 2003 hangs up at the end
  ticket|ticketfix)
            pjphone 2003 192.0.2.23 50000 30 --auto-answer 200; phone 2002 192.0.2.22 $B2 40000 30 "$AUTO"
            pjphone 2001 192.0.2.21 30000 30; sleep 3
            pj 0 2001 m sip:2002@lab.sip; ctl 4 $B2 hold; ctl 2 $B2 dial sip:2003@lab.sip; ctl 4 $B2 hold
            read -r CID FTAG TTAG <<< "$(dialog_ids 192.0.2.23)"   # From tag = 2002's, To tag = 2003's
            if [ $CASE = ticket ]; then RT="$FTAG"; RF="$TTAG"; else RT="$TTAG"; RF="$FTAG"; fi
            ctl 2 $B2 line 1; ctl 0 $B2 transfer "<sip:2003@lab.sip?Replaces=$CID%3Bto-tag%3D$RT%3Bfrom-tag%3D$RF>"
            if [ $CASE = ticketfix ]; then pj 8 2003 h; else sleep 8; fi; sleep 2 ;;   # ticket: nobody ends 2002-2003
  # RFC 3892 / RFC 5589 8: "Bob" 2002 (pjsua) holds "Alice" 2001 and transfers her (x) to "Carol" 2003 (pjsua, auto
  # answer): pjsua puts Referred-By (its From) on every REFER. referredby: Alice is pjsua, which copies Referred-By into
  # its INVITE to Carol; referredby-baresip: Alice is baresip, which does not. Carol's log says who it thinks is calling
  referredby|referredby-baresip)
            NAMES[2003]=Carol; NAMES[2002]=Bob; NAMES[2001]=Alice
            pjphone 2003 192.0.2.23 50000 30 --auto-answer 200; pjphone 2002 192.0.2.22 40000 30 --auto-answer 200
            if [ $CASE = referredby ]; then pjphone 2001 192.0.2.21 30000 30; sleep 3; pj 0 2001 m sip:2002@lab.sip
            else phone 2001 192.0.2.21 $B1 30000 30; sleep 3; ctl 0 $B1 dial sip:2002@lab.sip; fi
            pj 4 2002 H; pj 3 2002 x sip:2003@lab.sip; pj 1 2003 ""; pj 7 2003 h; sleep 3 ;;   # "": Carol's screen
  # RFC 5589 6.3.1: the target is busy. xferfail: three pjsua phones; 2003 answers every call 486 Busy Here (a phone set
  # to busy); 2002 holds 2001 (H), transfers it (x), gets the NOTIFY with 486 and takes 2001 back off hold (v), then
  # hangs up. xferfail-baresip: baresip 2002 and 2001, SIPp 2003 (180, then 486): the baresip transferor logs "transfer
  # failed: 486 Busy Here" and hangs up on 2001 anyway
  xferfail) pjphone 2003 192.0.2.23 50000 30 --auto-answer 486; pjphone 2002 192.0.2.22 40000 30 --auto-answer 200
            pjphone 2001 192.0.2.21 30000 30; sleep 3
            pj 0 2001 m sip:2002@lab.sip; pj 4 2002 H; pj 3 2002 x sip:2003@lab.sip; pj 5 2002 v; pj 5 2002 h; sleep 2 ;;
  xferfail-baresip)
            sipp_reg 2003 192.0.2.23
            timeout 25 sipp -sf $S/uas-busy.xml -s 2003 -i 192.0.2.23 -p 5060 -m 1 -timeout 25s -nostdin \
              > captures/$NAME.sipp.log 2>&1 &
            phone 2002 192.0.2.22 $B2 40000 30 "$AUTO"; phone 2001 192.0.2.21 $B1 30000 30; sleep 3
            ctl 0 $B1 dial sip:2002@lab.sip; ctl 4 $B2 hold; ctl 3 $B2 transfer sip:2003@lab.sip; sleep 8 ;;
  # RFC 5589 6.3.2: the target rings and nobody answers (pjsua 2003 answers 180 and nothing more); the proxy gives up
  # after fr_inv_timeout (30 s): CANCEL to 2003, 408 to 2001, NOTIFY 408; 2002 (pjsua) takes 2001 back (v), hangs up
  xfernoanswer)
            pjphone 2003 192.0.2.23 50000 60 --auto-answer 180; pjphone 2002 192.0.2.22 40000 60 --auto-answer 200
            pjphone 2001 192.0.2.21 30000 60; sleep 3
            pj 0 2001 m sip:2002@lab.sip; pj 4 2002 H; pj 3 2002 x sip:2003@lab.sip; pj 34 2002 v; pj 5 2002 h; sleep 2 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x pjsua 2>/dev/null
for p in "${HOLDERS[@]}"; do kill "$p" 2>/dev/null; done; rm -f /tmp/pjsua-*.in
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
R="-o rtp.heuristic_rtp:TRUE"
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap $R -Y "rtp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.cfg.diff 2>/dev/null
done
python3 pcap_messages.py captures/$NAME.pcap >/dev/null
cat captures/$NAME.txt | grep -v REGISTER | grep -v "401 Unauth"
echo "=== rtp ==="; cat captures/$NAME.rtp.txt
