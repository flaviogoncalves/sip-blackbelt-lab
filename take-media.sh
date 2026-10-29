#!/bin/bash
# sip-lab takes for chapter 5 (SDP and media). Same plumbing as take-route.sh. baresip phones load opus, G.722 and G.711
# (in that order of preference) and print RTP statistics at hang-up (rtp_stats); SIPp plays the side that needs a
# hand-written SDP (three codecs and a video stream, G.729, in-band DTMF) or a trunk that takes G.729 only.
#   sudo ./take-media.sh <case> <name>
# Cases: basic rtcpmux pcmu g722 opus offer recvonly dtmf dtmfinfo inband netem ticket ticketfix
# Writes captures/<name>.pcap (SIP + RTP + RTCP + ICMP on lo), .txt (SIP summary), .rtp.txt (RTP streams), .media.txt,
# .rtpfields.txt (every RTP packet: time, addresses, ports, payload type, seq, timestamp, SSRC, sizes), .rtcp.txt and
# .dtmf.txt. Leaves nothing running.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
mkdir -p /run/opensips
S=scenarios
B1=4401; B2=4402
sed "s/@DIGEST_ALGS@/MD5/" opensips/lab.cfg > /tmp/lab-take.cfg
/usr/sbin/opensips -F -f /tmp/lab-take.cfg > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params] [config lines]
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" "${6:-}")
  sed -i -e 's|^#\(module[[:space:]]*opus.so\)|\1|' -e 's|^#\(module[[:space:]]*g722.so\)|\1|' \
         -e 's|^rtp_stats.*|rtp_stats\t\tyes|' "$d/config"
  if [ -n "${7:-}" ]; then  # "key value": replace the key's line (baresip reads the first one), or add it
    local k=${7%% *} v=${7#* }
    if grep -q "^$k[[:space:]]" "$d/config"; then sed -i "s|^$k[[:space:]].*|$k\t\t$v|" "$d/config"
    else printf '%s\t\t%s\n' "$k" "$v" >> "$d/config"; fi
  fi
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
sipp_uas() {  # sipp_uas <scenario> <seconds>
  timeout "$2" sipp -sf $S/$1 -s 2002 -i 192.0.2.22 -p 5060 -mp 40000 -m 1 -timeout "${2}s" -nostdin \
    > captures/$NAME.uas.log 2>&1 &
}
sipp_uac() {  # sipp_uac <scenario> <seconds> [-set ...]
  local sc=$1 t=$2; shift 2
  sipp_reg 2001 192.0.2.21
  timeout "$t" sipp 192.0.2.10:5060 -sf $S/$sc -s 2001 -set callee 2002 "$@" -auth_uri 2002@lab.sip -au 2001 \
    -ap lab-2001-pass -i 192.0.2.21 -p 5060 -mp 30000 -m 1 -timeout "${t}s" -nostdin > captures/$NAME.uac.log 2>&1 || echo "call failed"
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
dial() { ctl 0 $B1 dial sip:2002@lab.sip; }
callee() {  # callee <seconds> [account params] [config lines]: baresip 2002, auto answer after 2 s
  phone 2002 192.0.2.22 $B2 40000 "$1" ";answermode=auto;answerdelay=2000${2:-}" "${3:-}"
}
digits() { for d in 1 2 3 '#'; do ctl 0.6 $B1 sndcode "$d"; done; }

case $CASE in
  # one call with every codec the phones load (opus, G722, PCMU, PCMA): the SDP of a real offer; RTCP on port + 1
  basic)    callee 20; phone 2001 192.0.2.21 $B1 30000 20; sleep 3; dial; ctl 14 $B1 hangup; sleep 2 ;;
  # the same call with rtcp_mux on both phones: RTCP shares the RTP port (a=rtcp-mux)
  rtcpmux)  callee 20 "" "rtcp_mux yes"; phone 2001 192.0.2.21 $B1 30000 20 "" "rtcp_mux yes"
            sleep 3; dial; ctl 14 $B1 hangup; sleep 2 ;;
  # one codec forced on both phones: packet size and rate for the bandwidth sum
  pcmu|g722|opus)
            case $CASE in pcmu) C="PCMU/8000/1" ;; g722) C="G722/16000/1" ;; opus) C="opus/48000/2" ;; esac
            callee 16 ";audio_codecs=$C"; phone 2001 192.0.2.21 $B1 30000 16 ";audio_codecs=$C"
            sleep 3; dial; ctl 10 $B1 hangup; sleep 2 ;;
  # SIPp offers PCMU, PCMA, G722, telephone-event and a video stream; baresip 2002 answers (direction from the case)
  offer|recvonly)
            [ $CASE = offer ] && DIR=sendrecv || DIR=recvonly
            callee 18; sleep 2; sipp_uac call-offer.xml 14 -set dir $DIR ;;
  # DTMF as RFC 4733 telephone-events (baresip default), then as SIP INFO; PCMU on both phones (8 kHz clock)
  dtmf|dtmfinfo)
            P=";audio_codecs=PCMU/8000/1"; [ $CASE = dtmfinfo ] && P="$P;dtmfmode=info"
            callee 20 ";audio_codecs=PCMU/8000/1"; phone 2001 192.0.2.21 $B1 30000 20 "$P"; sleep 3; dial; sleep 5; digits; ctl 3 $B1 hangup; sleep 2 ;;
  # in-band DTMF: SIPp offers PCMU only and plays the digits as tones inside the audio
  inband)   callee 18; sleep 2; sipp_uac call-inband.xml 14 ;;
  # a call with impairment on 2001's media only (tc netem on lo, ports 30000-30015): loss, delay and jitter
  netem)    callee 26; phone 2001 192.0.2.21 $B1 30000 26
            tc qdisc add dev lo root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
            tc qdisc add dev lo parent 1:4 handle 40: netem delay 40ms 20ms loss 5%
            tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport 30000 0xfff0 flowid 1:4
            tc -s qdisc show dev lo > captures/$NAME.netem.txt
            sleep 3; dial; ctl 18 $B1 hangup; sleep 2
            tc -s qdisc show dev lo >> captures/$NAME.netem.txt; tc qdisc del dev lo root ;;
  # the 488 ticket: the phone offers PCMA only, the trunk (SIPp at 192.0.2.22) takes G.729 only
  ticket)   sipp_reg 2002 192.0.2.22; sipp_uas uas-g729only.xml 12
            phone 2001 192.0.2.21 $B1 30000 10 ";audio_codecs=PCMA/8000/1"; sleep 3; dial; sleep 5 ;;
  # the fix: an offer with G.729 to the same trunk gets 200 OK
  ticketfix) sipp_reg 2002 192.0.2.22; sipp_uas uas-g729only.xml 14; sleep 1; sipp_uac call-g729.xml 10 ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
R="-o rtp.heuristic_rtp:TRUE -o rtcp.heuristic_rtcp:TRUE"
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap $R -Y "rtp or rtcp or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
tshark -r captures/$NAME.pcap $R -Y "rtp and not rtpevent" -T fields -E header=y -e frame.number -e frame.time_relative \
  -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type -e rtp.seq -e rtp.timestamp -e rtp.ssrc -e rtp.marker \
  -e frame.len -e ip.len -e udp.length 2>/dev/null > captures/$NAME.rtpfields.txt
tshark -r captures/$NAME.pcap $R -Y rtcp -V 2>/dev/null > captures/$NAME.rtcp.txt
tshark -r captures/$NAME.pcap $R -Y 'rtpevent or sip.Method == "INFO"' -T fields -E header=y -e frame.number \
  -e frame.time_relative -e ip.src -e ip.dst -e rtp.p_type -e rtp.seq -e rtp.timestamp -e rtp.marker -e rtpevent.event_id \
  -e rtpevent.end_of_event -e rtpevent.duration -e sip.Method -e sip.msg_body 2>/dev/null > captures/$NAME.dtmf.txt
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt 2>/dev/null
done
cat captures/$NAME.txt; echo "=== rtp ==="; cat captures/$NAME.rtp.txt
