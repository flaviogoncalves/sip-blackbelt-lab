#!/bin/bash
# sip-lab takes for section 3 part B (Wireshark for VoIP). Same plumbing as take-media.sh and take-errors.sh: baresip
# phones (baresip-phone.sh, driven by bctl.py, PCMU forced), SIPp for the load (scenarios/load-uac.xml and load-uas.xml,
# RTP from scenarios/voice-pcmu.wav with rtp_stream: one RTP port per call).
#   sudo ./take-wireshark.sh <case> <name>
# Cases:
#   midcall  a baresip call 2001 -> 2002 captured from 3 s after the answer (RTP and RTCP with no INVITE, no SDP, then
#            the BYE): <name>.pcap; the same call from before the INVITE: <name>-full.pcap
#   busy     ~60 s of load through the proxy (4.5 calls/s from a SIPp gateway at 192.0.2.21:5070, 407 answered) with a
#            mix from an injection file made with a fixed seed: 70% 2002 (180, 200, RTP both ways, BYE after 3-6 s),
#            10% 2004 (486), 10% 2009 (not registered: 404), 10% 2006 (503, which the proxy turns into 500); plus two
#            baresip calls 2001 -> 2003 in the middle. <name>.mix.txt = planned and counted outcomes
#   ring     a shorter load while a student's dumpcap ring buffer runs, then the student's commands (ls, capinfos,
#            mergecap, tshark, editcap) and both sides of the section 4 NAT take (s4b-nat.home.pcap and s4b-nat.pcap,
#            uploaded into captures/ beforehand), each command and its output in <name>.terminal.txt
#   ticket   one 10-minute baresip call 2001 -> 2002 where 2002's media (RTP and RTCP, ports 40000-40015) is lost twice
#            (tc netem loss 100% on lo): 4 s from 3:05 and 6 s from 7:40 after the answer. <name>.netem.txt, <name>.gaps.txt
# Writes captures/<name>.pcap (SIP + RTP + RTCP + ICMP on lo), .txt (SIP summary), .messages.txt (pcap_messages.py),
# .rtp.txt (RTP streams), .media.txt and the logs of every element. Leaves nothing running (tc removed).
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
LAB=$PWD
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x dumpcap 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
mkdir -p /run/opensips
S=scenarios
[ -f $S/voice-pcmu.wav ] || (cd $S && python3 make_pcmu_wav.py)   # the load calls' audio (generated, not in git)
B1=4401; B2=4402; B3=4403
rm -f captures/$NAME.* captures/$NAME-full.*

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
  # the load's callees: 2004 (busy) and 2006 (overloaded) register too, so they need passwords
  busy|ring)
    edit $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n' \
         $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n\t\tcase "2004": $avp(passspec) = "lab-2004-pass"; break;\n\t\tcase "2006": $avp(passspec) = "lab-2006-pass"; break;\n' ;;
esac
cmp -s $PLAIN $CFG || diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff   # only when the take changes lab.cfg

/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
TCPD=
[ $CASE != ring ] && { tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1; }

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds> [account params]: PCMU only, RTP statistics at hang-up
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" ";audio_codecs=PCMU/8000/1${6:-}")
  sed -i -e 's|^rtp_stats.*|rtp_stats\t\tyes|' "$d/config"
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
stamp() { echo "$(date +%s.%N) $*" >> captures/$NAME.events.txt; }

# the load: an injection file (fixed seed: the same mix every run), the callees (one SIPp at 192.0.2.22, registered
# as 2002, 2004 and 2006) and the caller (a SIPp gateway at 192.0.2.21:5070, user 2001, answering the proxy's 407)
load_prepare() {  # load_prepare <calls> <seed>
  python3 - "$1" "$2" > captures/$NAME.calls.csv <<'EOF'
import random, sys
n, seed = int(sys.argv[1]), int(sys.argv[2])
rng = random.Random(seed)
mix = [("2002", 0.7), ("2004", 0.1), ("2009", 0.1), ("2006", 0.1)]   # answered, busy, not registered, overloaded
calls = [num for num, share in mix[1:] for _ in range(round(n * share))]
calls += ["2002"] * (n - len(calls))
rng.shuffle(calls)
print("SEQUENTIAL")
for num in calls:
    print(f"{num};{rng.randint(3000, 6000)};")   # number called; how long an answered call lasts (ms)
EOF
  for u in 2002 2004 2006; do sipp_reg $u 192.0.2.22; done
  timeout 150 sipp -sf $S/load-uas.xml -i 192.0.2.22 -p 5060 -min_rtp_port 41000 -max_rtp_port 41999 -timeout 150s \
    -nostdin -trace_err -error_file captures/$NAME.uas.errors.log > captures/$NAME.uas.log 2>&1 & UASP=$!
  sleep 1
}
load_run() {  # load_run <calls> <calls per second>
  stamp "load start"
  timeout 150 sipp 192.0.2.10:5060 -sf $S/load-uac.xml -inf captures/$NAME.calls.csv -s 2001 -au 2001 \
    -ap lab-2001-pass -auth_uri lab.sip -i 192.0.2.21 -p 5070 -min_rtp_port 31000 -max_rtp_port 31999 \
    -r "$2" -l 200 -m "$1" -timeout 150s -nostdin -trace_err -error_file captures/$NAME.uac.errors.log \
    -trace_stat -stf captures/$NAME.uac.stat.csv > captures/$NAME.uac.log 2>&1 || echo "load caller ended with an error"
  stamp "load end"
  sleep 2; kill $UASP 2>/dev/null
}

case $CASE in
  midcall)
    phone 2002 192.0.2.22 $B2 40000 25 ";answermode=auto;answerdelay=2000"; phone 2001 192.0.2.21 $B1 30000 25
    sleep 3; stamp "dial"; ctl 0 $B1 dial sip:2002@lab.sip
    sleep 5   # the answer comes ~2 s after the dial; the mid-call capture starts ~3 s later
    tcpdump -i lo -U -s 0 -w captures/$NAME-mid.pcap 'udp or icmp' 2>/dev/null & TCPM=$!; stamp "mid-call capture start"
    sleep 10; stamp "hangup"; ctl 0 $B1 hangup; sleep 2
    kill $TCPM; stamp "mid-call capture stop"; sleep 1 ;;
  busy)
    load_prepare 270 3913
    phone 2003 192.0.2.23 $B3 50000 80 ";answermode=auto;answerdelay=2000"; phone 2001 192.0.2.21 $B1 30000 80; sleep 3
    (  # two real phone calls in the middle of the load
      ctl 18 $B1 dial sip:2003@lab.sip; stamp "baresip call 1"; ctl 10 $B1 hangup
      ctl 8 $B1 dial sip:2003@lab.sip; stamp "baresip call 2"; ctl 10 $B1 hangup
    ) & PH=$!
    load_run 270 4.5
    wait $PH ;;
  ring)
    for f in /tmp/ring_*.pcapng captures/all.pcapng captures/onecall.pcapng captures/window.pcapng captures/both.pcapng \
             captures/onecall.messages.txt; do rm -f "$f"; done
    chown lab:lab captures   # the student's working directory (the takes create it as root)
    T=captures/$NAME.terminal.txt; : > $T
    term() {  # term <command>: run it as the student (user lab, in ~/lab/captures); the prompt, the command, the output
      printf 'lab@sip-lab:~/lab/captures$ %s\n' "$1" >> $T
      runuser -u lab -- bash -c "cd $LAB/captures && $1" >> $T 2>&1
    }
    load_prepare 160 3914
    # the student's ring buffer: 10 s per file, 4 files kept; stopped with ctrl-C after the load
    C='sudo dumpcap -i lo -b duration:10 -b files:4 -w /tmp/ring.pcapng'
    printf 'lab@sip-lab:~/lab/captures$ %s\n' "$C" >> $T
    runuser -u lab -- bash -c "cd $LAB/captures && exec $C" > /tmp/ring-dumpcap.out 2>&1 & DC=$!
    sleep 2; load_run 160 2.5; sleep 2
    pkill -INT -x dumpcap; wait $DC
    # as a terminal shows it: dumpcap rewrites its packet counter in place (\r), and prints its totals after the ctrl-C
    python3 - /tmp/ring-dumpcap.out >> $T <<'EOF'
import sys
lines = [l.split("\r")[-1].rstrip() for l in open(sys.argv[1], newline="").read().split("\n")]
while lines and not lines[-1]:
    lines.pop()
i = next((k for k, l in enumerate(lines) if l.startswith("Packets captured")), len(lines))
print("\n".join(lines[:i] + ["^C"] + lines[i:]))
EOF
    term 'ls -l /tmp/ring_*'
    term 'sudo chown lab: /tmp/ring_*'
    FIRST=$(ls /tmp/ring_*.pcapng | head -1)
    term "capinfos -c -s -u -a -e $FIRST"
    term 'mergecap -w all.pcapng /tmp/ring_*.pcapng'
    term 'capinfos -c -s -u -a -e all.pcapng'
    term 'tshark -r all.pcapng -Y sip.Method==INVITE -T fields -e sip.Call-ID -e frame.time_relative | head -12'
    # the call the lesson cuts out: the first INVITE in the merged file whose call was answered (200 to the caller)
    CID=$(python3 - <<'EOF'
import subprocess
def f(flt, *fields):
    cmd = ["tshark", "-r", "captures/all.pcapng", "-Y", flt, "-T", "fields"]
    for x in fields:
        cmd += ["-e", x]
    return subprocess.run(cmd, capture_output=True, text=True).stdout.split()
answered = set(f('sip.Status-Code == 200 && sip.CSeq.method == "INVITE" && ip.dst == 192.0.2.21', "sip.Call-ID"))
byes = set(f('sip.Status-Code == 200 && sip.CSeq.method == "BYE" && ip.dst == 192.0.2.21', "sip.Call-ID"))
seen = []
for c in f("sip.Method == INVITE", "sip.Call-ID"):
    if c not in seen:
        seen.append(c)
print(next(c for c in seen[:4] if c in answered and c in byes))
EOF
)
    term "tshark -r all.pcapng -Y 'sip.Call-ID == \"$CID\" && sdp' -T fields -e frame.number -e ip.src -e sip.CSeq -e sip.Status-Code -e sdp.media.port"
    PORT=$(tshark -r captures/all.pcapng -Y "sip.Call-ID == \"$CID\" && sdp && ip.src == 192.0.2.21" -T fields \
      -e sdp.media.port 2>/dev/null | head -1)
    term "tshark -r all.pcapng -Y 'sip.Call-ID == \"$CID\" || udp.port == $PORT' -w onecall.pcapng"
    term 'tshark -r onecall.pcapng -Y sip'
    term 'tshark -r onecall.pcapng -q -z rtp,streams'
    # a 10 s window of the merged file, from the second the cut call starts
    A=$(tshark -r captures/onecall.pcapng -T fields -e frame.time_epoch -c 1 2>/dev/null)
    WA=$(date -d "@${A%.*}" "+%Y-%m-%d %H:%M:%S"); WB=$(date -d "@$(( ${A%.*} + 10 ))" "+%Y-%m-%d %H:%M:%S")
    term "editcap -A \"$WA\" -B \"$WB\" all.pcapng window.pcapng"
    term 'capinfos -c -a -e window.pcapng'
    # both sides of the section 4 NAT take: the home side of the router and the internet side
    if [ -f captures/s4b-nat.home.pcap ] && [ -f captures/s4b-nat.pcap ]; then
      term 'capinfos -a -e s4b-nat.home.pcap s4b-nat.pcap'
      term 'tshark -r s4b-nat.home.pcap -Y sip.Method==REGISTER -T fields -e frame.time -e sip.Call-ID -e sip.CSeq'
      RID=$(tshark -r captures/s4b-nat.home.pcap -Y sip.Method==REGISTER -T fields -e sip.Call-ID 2>/dev/null | head -1)
      term 'mergecap -w both.pcapng s4b-nat.home.pcap s4b-nat.pcap'
      term "tshark -r both.pcapng -Y 'sip.Call-ID == \"$RID\"' -T fields -e frame.interface_id -e frame.time -e ip.src -e udp.srcport -e ip.dst -e sip.CSeq -e sip.Status-Code"
    else
      echo "### s4b-nat.home.pcap / s4b-nat.pcap not in captures/: both-sides part skipped" >> $T
    fi
    echo "$CID $PORT" > captures/$NAME.onecall.txt ;;
  ticket)
    phone 2002 192.0.2.22 $B2 40000 640 ";answermode=auto;answerdelay=2000"; phone 2001 192.0.2.21 $B1 30000 640
    # netem ready but harmless (loss 0%) on 2002's media ports; switched to 100% for the two gaps
    tc qdisc add dev lo root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    tc qdisc add dev lo parent 1:4 handle 40: netem loss 0%
    tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip sport 40000 0xfff0 flowid 1:4
    sleep 3; stamp "dial"; ctl 0 $B1 dial sip:2002@lab.sip; sleep 2; stamp "answered (about)"
    gap() {  # gap <seconds to wait> <seconds lost>
      sleep "$1"; tc qdisc change dev lo parent 1:4 handle 40: netem loss 100%; stamp "netem loss 100% on 2002's media"
      sleep "$2"; tc qdisc change dev lo parent 1:4 handle 40: netem loss 0%; stamp "netem loss 0% (media back)"
    }
    gap 185 4; gap 271 6
    sleep 134; stamp "hangup"; ctl 0 $B1 hangup; sleep 2
    tc -s qdisc show dev lo > captures/$NAME.tc.txt; tc qdisc del dev lo root ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x dumpcap 2>/dev/null
[ -n "$TCPD" ] && kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS 2>/dev/null; sleep 1
tc qdisc del dev lo root 2>/dev/null
[ $CASE = midcall ] && { mv captures/$NAME.pcap captures/$NAME-full.pcap; mv captures/$NAME-mid.pcap captures/$NAME.pcap; }

R="-o rtp.heuristic_rtp:TRUE -o rtcp.heuristic_rtcp:TRUE"
summary() {  # summary <pcap without .pcap>
  local P=$1
  tshark -r $P.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
    2>/dev/null > $P.txt
  tshark -r $P.pcap $R -q -z rtp,streams 2>/dev/null > $P.rtp.txt
  tshark -r $P.pcap $R -Y "rtp or rtcp or icmp" -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst \
    -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > $P.media.txt
  (cd captures && python3 ../pcap_messages.py "$(basename $P).pcap")
}
case $CASE in
  midcall)
    summary captures/$NAME; summary captures/$NAME-full
    { echo "### protocols as Wireshark shows them with no settings (no SDP in the capture: RTP and RTCP are plain UDP)"
      tshark -r captures/$NAME.pcap -T fields -e _ws.col.Protocol 2>/dev/null | sort | uniq -c
      echo "### with the rtp_udp and rtcp_udp heuristics on (Analyze > Enabled Protocols)"
      tshark -r captures/$NAME.pcap $R -T fields -e _ws.col.Protocol 2>/dev/null | sort | uniq -c
      echo "### the full capture (with the INVITE and its SDP), no settings"
      tshark -r captures/$NAME-full.pcap -T fields -e _ws.col.Protocol 2>/dev/null | sort | uniq -c
      echo "### UDP conversations of the mid-call capture"
      tshark -r captures/$NAME.pcap -q -z conv,udp 2>/dev/null
    } > captures/$NAME.decode.txt ;;
  busy)
    summary captures/$NAME
    tshark -r captures/$NAME.pcap -q -z sip,stat 2>/dev/null > captures/$NAME.sipstat.txt
    python3 - captures/$NAME > captures/$NAME.mix.txt <<'EOF'
import collections, subprocess, sys
base = sys.argv[1]
names = {"2002": "answered (180, 200)", "2004": "busy (486)", "2009": "not registered (404)", "2006": "overloaded (503)"}
planned = collections.Counter(l.split(";")[0] for l in open(base + ".calls.csv").read().split("\n")[1:] if l)
def rows(flt, *fields):
    cmd = ["tshark", "-r", base + ".pcap", "-Y", flt, "-T", "fields", "-E", "separator=;"]
    for x in fields:
        cmd += ["-e", x]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return sorted(set(tuple(l.split(";")) for l in out.splitlines() if l))
print("planned (calls.csv, seed fixed):")
for k in ["2002", "2004", "2009", "2006"]:
    print(f"  {planned[k]:4d}  {k}  {names[k]}")
print(f"  {sum(planned.values()):4d}  total")
def count(title, flt):
    c = collections.Counter()
    for cid, num, code, reason in rows(flt, "sip.Call-ID", "sip.to.user", "sip.Status-Code", "sip.Status-Line"):
        c[(num, code, reason)] += 1
    print(title)
    for (num, code, line), n in sorted(c.items()):
        print(f"  {n:4d}  to {num}: {line}")
    print(f"  {sum(c.values()):4d}  total")
F = 'sip.Status-Code >= 200 && sip.CSeq.method == "INVITE" && '
count("\ncounted in the pcap, one per Call-ID (retransmissions not counted):\n"
      "final responses to the gateway's authenticated INVITEs (proxy 192.0.2.10 -> gateway 192.0.2.21:5070, CSeq 2):",
      F + "ip.dst == 192.0.2.21 && udp.dstport == 5070 && sip.CSeq.seq == 2")
count("final responses from the callees (192.0.2.22 -> proxy 192.0.2.10):", F + "ip.src == 192.0.2.22")
count("407 challenges to the gateway's first INVITEs (CSeq 1):", F + "ip.dst == 192.0.2.21 && udp.dstport == 5070 && sip.CSeq.seq == 1")
count("the phones' calls (baresip 2001 at 192.0.2.21:5060 -> 2003 at 192.0.2.23), final responses:",
      F + "ip.dst == 192.0.2.21 && udp.dstport == 5060")
EOF
    cat captures/$NAME.mix.txt ;;
  ring)
    (cd captures && python3 ../pcap_messages.py onecall.pcapng) ;;
  ticket)
    summary captures/$NAME
    python3 - captures/$NAME > captures/$NAME.gaps.txt <<'EOF'
import subprocess, sys
base = sys.argv[1]
def rtp(src):
    cmd = ["tshark", "-r", base + ".pcap", "-o", "rtp.heuristic_rtp:TRUE", "-Y", f"rtp && ip.src == {src}",
           "-T", "fields", "-e", "frame.time_epoch", "-e", "rtp.seq"]
    return [tuple(l.split("\t")) for l in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()]
first = float(subprocess.run(["tshark", "-r", base + ".pcap", "-c", "1", "-T", "fields", "-e", "frame.time_epoch"],
                             capture_output=True, text=True).stdout)
ok = subprocess.run(["tshark", "-r", base + ".pcap", "-Y", 'sip.Status-Code == 200 && sip.CSeq.method == "INVITE"',
                     "-T", "fields", "-e", "frame.time_epoch"], capture_output=True, text=True).stdout.split()
answer = float(ok[0])
print(f"200 OK at {answer - first:.3f} s into the capture (call time 0:00 below)")
for src, who in [("192.0.2.22", "2002 -> 2001"), ("192.0.2.21", "2001 -> 2002")]:
    pk = rtp(src)
    print(f"RTP {who}: {len(pk)} packets")
    for (t1, s1), (t2, s2) in zip(pk, pk[1:]):
        d = float(t2) - float(t1)
        if d > 0.1:
            a = float(t1) - answer
            print(f"  gap {d:.3f} s after seq {s1} at {a:.3f} s ({int(a // 60)}:{a % 60:06.3f} call time, "
                  f"{float(t1) - first:.3f} s capture time), next seq {s2} (seq jump {(int(s2) - int(s1)) % 65536})")
print("\nnetem switches (from the take's events.txt):")
for line in open(base + ".events.txt"):
    t, what = line.split(" ", 1)
    print(f"  {float(t) - answer:9.3f} s call time  {float(t) - first:9.3f} s capture time  {what.strip()}")
EOF
    cp captures/$NAME.events.txt captures/$NAME.netem.txt; cat captures/$NAME.tc.txt >> captures/$NAME.netem.txt
    cat captures/$NAME.gaps.txt ;;
esac
# baresip logs its local address (the droplet's public IP): mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME-full.*txt \
    captures/onecall.messages.txt 2>/dev/null
done
[ -s captures/$NAME.txt ] && tail -5 captures/$NAME.txt; [ -s captures/$NAME.rtp.txt ] && cat captures/$NAME.rtp.txt
ls -l captures/$NAME* | awk '{print $5, $9}'
