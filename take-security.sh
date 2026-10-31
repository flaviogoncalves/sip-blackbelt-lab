#!/bin/bash
# sip-lab takes for section 7 part A (security): SIP over TLS, debugging encrypted calls, SRTP, a certificate ticket.
# Same plumbing as take-qosfax.sh. Everything stays on the box: the CA and the certificates are made here for the take
# (tls/, never published: only certificates and their text dumps are copied out, never a private key).
#   sudo ./take-security.sh <case> <name>
# Cases (lesson):
#   tls (7.2)                  OpenSIPS on TLS 5061 (tls_mgm + tls_openssl + proto_tls) with a lab CA and a certificate
#                              for lab.sip (subjectAltName DNS:lab.sip and URI:sip:lab.sip, RFC 5922); openssl s_client
#                              with TLS 1.3, 1.2, 1.1 and 1.0 (the last two refused: RFC 8996); then baresip 2001 and
#                              2002 register and call over TLS (sip: URIs with ;transport=tls: baresip 1.1.0 refuses a
#                              sips: account). terminal.txt
#   tlsdebug (7.3)             the same TLS call, opaque in the pcap; openssl s_client sends a REGISTER over TLS and
#                              writes a key log (-keylogfile), with which tshark decrypts that connection; OpenSIPS
#                              mirrors every SIP message and TLS event as HEP to lab/hep_collector.py; the server log
#                              lines. terminal.txt
#   tlsdebug12 (7.3)           the server allows TLS 1.2 only: the phones' own call is decrypted with the master secrets
#                              OpenSIPS reported in its HEP TLS events (hep_keylog.py). terminal.txt
#   sdes dtls (7.4)            baresip 2001 calls baresip 2002 with SRTP keyed by SDES (RTP/SAVP + a=crypto, RFC 4568)
#                              or by DTLS-SRTP (UDP/TLS/RTP/SAVPF + a=fingerprint + a=setup, RFC 5763/5764). Signalling
#                              over UDP, so the SDP (and the SDES key in it) is readable in the pcap
#   mismatch (7.4)             2001 requires SRTP (srtp-mand) and calls 2002, which has no SRTP configured; then the
#                              reverse: 2001 plain calls 2002 requiring SRTP
#   ticket ticketfix (7.5)     "TLS calls fail since the certificate was renewed": the renewed certificate names the
#                              host (proxy1.lab.sip), not the domain the phones dial (lab.sip): the phones refuse the
#                              handshake. Fix: a certificate with subjectAltName DNS:lab.sip, and an OpenSIPS restart
#                              (tls_mgm:reload only reloads TLS domains kept in a database)
# Phones: 2001 = 192.0.2.21 (caller), 2002 = 192.0.2.22 (callee). For TLS each phone runs in its own network namespace
# (ph21, ph22, joined to the box by a veth pair v21/v22): baresip does not bind its outgoing TCP connections to its
# address, so on the box itself every connection would come from 192.0.2.10. In the namespaces they come from the
# phone's own address, as from a separate host.
# Writes captures/<name>.pcap (merged from lo, v21 and v22), .txt (SIP or TLS summary), .messages.txt (pcap_messages.py
# for UDP SIP; for TLS cases the SIP as the HEP collector received it), .hep.txt, .tls.txt (TLS records), .rtp.txt,
# .media.txt, .payload.txt (the first RTP payload bytes of each stream), .certs.txt, the logs of every element,
# .cfg.diff (TLS changes) and .hep.cfg.diff (the HEP mirror), .terminal.txt; tlsdebug(12): .keys.log (the key log),
# .decrypted.txt (tshark with it), .hepkeys.txt; dtls: .dtls.txt. Leaves nothing running, lab.cfg untouched.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
L=$(pwd)
unhost() {  # remove the phone namespaces and their rules (and give the addresses back to their dummies: net.sh)
  pkill -f "dnsmasq.*/tmp/dnsmasq-ph" 2>/dev/null; rm -f /tmp/dnsmasq-ph2?.pid
  for o in 21 22; do
    ip netns del ph$o 2>/dev/null; ip link del v$o 2>/dev/null
    while iptables -D INPUT -i v$o -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -i v$o -j ACCEPT 2>/dev/null; do :; done
  done
  ./net.sh >/dev/null
}
unhost
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -x pjsua 2>/dev/null
pkill -f hep_collector.py 2>/dev/null; sleep 1
mkdir -p /run/opensips
rm -f captures/$NAME.*
T=captures/$NAME.terminal.txt
term() {  # term <command>: typed as user lab in ~/lab; the prompt, the command and its output go to the terminal file
  printf 'lab@sip-lab-2:~/lab$ %s\n' "$1" >> $T
  env -i HOME=/home/lab USER=lab LOGNAME=lab PATH=/usr/local/bin:/usr/bin:/bin \
    setpriv --reuid=lab --regid=lab --init-groups bash -c "cd /home/lab/lab && $1" >> $T 2>&1
}
quiet() { env -i HOME=/home/lab PATH=/usr/bin:/bin setpriv --reuid=lab --regid=lab --init-groups bash -c "cd $L && $1" >/dev/null 2>&1; }

# the lab PKI (tls/, owned by lab): a CA, and a certificate for the SIP domain lab.sip signed by it
CA_CMDS=(
  "mkdir -p tls && chmod 700 tls"
  "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls/ca.key -out tls/ca.crt -days 365 -subj '/O=sip-lab/CN=sip-lab CA'"
)
cert_cmds() {  # cert_cmds <name in the certificate>: the request and the CA's signature, written as tls/lab.sip.*
  CERT_CMDS=(
    "openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls/lab.sip.key -out tls/lab.sip.csr -subj '/O=sip-lab/CN=$1' -addext 'subjectAltName=DNS:$1,URI:sip:$1' -addext 'extendedKeyUsage=serverAuth'"
    "openssl x509 -req -in tls/lab.sip.csr -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -days 90 -copy_extensions copy -out tls/lab.sip.crt"
  )
}
SHOWCERT="openssl x509 -in tls/lab.sip.crt -noout -subject -issuer -dates -ext subjectAltName,extendedKeyUsage"
rm -rf tls
case $CASE in
  tls) for c in "${CA_CMDS[@]}"; do term "$c"; done; cert_cmds lab.sip; for c in "${CERT_CMDS[@]}"; do term "$c"; done
       term "$SHOWCERT" ;;
  ticket|ticketfix)  # the certificate that worked, then the renewal that went wrong (written over the same files)
       for c in "${CA_CMDS[@]}"; do quiet "$c"; done; cert_cmds lab.sip; for c in "${CERT_CMDS[@]}"; do quiet "$c"; done
       quiet "cp tls/lab.sip.crt tls/lab.sip-before-renewal.crt"
       cert_cmds proxy1.lab.sip; for c in "${CERT_CMDS[@]}"; do quiet "$c"; done ;;
  *)   for c in "${CA_CMDS[@]}"; do quiet "$c"; done; cert_cmds lab.sip; for c in "${CERT_CMDS[@]}"; do quiet "$c"; done ;;
esac

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
TLSCASE=no; case $CASE in tls|tlsdebug|tlsdebug12|ticket|ticketfix) TLSCASE=yes ;; esac
if [ $TLSCASE = yes ]; then
  METHOD="TLSv1_2-TLSv1_3"; [ $CASE = tlsdebug12 ] && METHOD="TLSv1_2"
  edit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\n\n# lesson 7.2: SIP over TLS on 5061 (RFC 3261 26.2), TLS 1.2 or 1.3 only (RFC 8996), with the certificate of the\n# SIP domain lab.sip (subjectAltName DNS:lab.sip, URI:sip:lab.sip; RFC 5922) signed by the lab CA\nsocket=tls:192.0.2.10:5061\nloadmodule "tls_openssl.so"\nloadmodule "tls_mgm.so"\nmodparam("tls_mgm", "server_domain", "lab.sip")\nmodparam("tls_mgm", "match_ip_address", "[lab.sip]192.0.2.10:5061")\nmodparam("tls_mgm", "certificate", "[lab.sip]'"$L"$'/tls/lab.sip.crt")\nmodparam("tls_mgm", "private_key", "[lab.sip]'"$L"$'/tls/lab.sip.key")\nmodparam("tls_mgm", "tls_method", "[lab.sip]'"$METHOD"$'")\n# the phones have no certificates of their own: the server does not ask them for one\nmodparam("tls_mgm", "verify_cert", "[lab.sip]0")\nmodparam("tls_mgm", "require_cert", "[lab.sip]0")\nloadmodule "proto_tls.so"\n# a phone\'s TLS port has no certificate behind it: reach the phone back over the connection it opened\nloadmodule "nathelper.so"\nmodparam("nathelper", "received_avp", "$avp(rcv)")\nmodparam("registrar", "received_avp", "$avp(rcv)")\n'
  edit $'route {\n' $'route {\n\t# lesson 7.2: what each TLS connection negotiated\n\tif ($(socket_in(proto){s.tolower}) == "tls")\n\t\txlog("L_NOTICE", "$rm from $si:$sp over TLS: $tls_version, cipher $tls_cipher_info, $tls_cipher_bits bits\\n");\n\n'
  edit $'\t\tif (!save("location"))' $'\t\tif ($(socket_in(proto){s.tolower}) == "tls")\n\t\t\tfix_nated_register();\t# store the connection\'s address with the contact\n\t\tif (!save("location"))'
  edit $'\trecord_route();\n' $'\trecord_route();\n\tif ($(socket_in(proto){s.tolower}) == "tls")\n\t\tfix_nated_contact();\t# the caller\'s Contact = its connection\n\tt_on_reply("tls");\n'
  edit $'# the lab\'s users' $'# lesson 7.2: the callee\'s Contact = its connection, too\nonreply_route[tls] {\n\tif ($(socket_in(proto){s.tolower}) == "tls")\n\t\tfix_nated_contact();\n}\n\n# the lab\'s users'
fi
cmp -s $PLAIN $CFG || diff $PLAIN $CFG > captures/$NAME.cfg.diff
if [ $TLSCASE = yes ]; then  # the HEP mirror (lesson 7.3), kept in its own diff
  BEFORE=/tmp/lab-take-tls.cfg; cp $CFG $BEFORE
  edit $'loadmodule "proto_tls.so"\n' $'loadmodule "proto_tls.so"\n\n# lesson 7.3: mirror every SIP message (as OpenSIPS saw it, after TLS) and every TLS connection event to a HEP\n# collector (lab/hep_collector.py on 192.0.2.10:9060; Homer in production)\nsocket=hep_udp:192.0.2.10:9061\nloadmodule "proto_hep.so"\nmodparam("proto_hep", "hep_id", "[collector]192.0.2.10:9060;transport=udp;version=3")\nmodparam("proto_tls", "trace_destination", "collector")\nmodparam("proto_tls", "trace_on", 1)\nloadmodule "tracer.so"\nmodparam("tracer", "trace_id", "[tid]uri=hep:collector")\n'
  edit $'route {\n' $'route {\n\ttrace("tid", "t", "sip");\t# lesson 7.3: this request, its replies and what OpenSIPS relays\n'
  diff $BEFORE $CFG > captures/$NAME.hep.cfg.diff
  KEYS=(); [ $CASE = tlsdebug12 ] && KEYS=(--keys captures/$NAME.hepkeys.txt)
  python3 hep_collector.py --listen 192.0.2.10:9060 "${KEYS[@]}" > captures/$NAME.hep.txt 2>&1 & sleep 1
fi

/usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
TCPDS=()
tcpdump -i lo -U -s 0 -w captures/$NAME.lo.pcap 'udp or tcp or icmp' 2>/dev/null & TCPDS+=($!); sleep 1

host() {  # host <octet>: the phone address 192.0.2.<octet> becomes its own host, namespace ph<octet>
  local o=$1
  ip addr del 192.0.2.$o/32 dev lab$o 2>/dev/null   # net.sh gives it back at the end
  ip netns add ph$o
  ip link add v$o type veth peer name lab$o netns ph$o   # lab<octet> inside: baresip-conf.sh's net_interface fits
  ip netns exec ph$o sh -c "echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; ip link set lo up
    ip addr add 192.0.2.$o/32 dev lab$o; ip link set lab$o up
    ip route add 192.0.2.10/32 dev lab$o; ip route add 192.0.2.0/24 via 192.0.2.10 dev lab$o"
  # the box answers lab.sip from /etc/hosts through systemd-resolved (127.0.0.53), which a namespace cannot reach:
  # a DNS server of its own for the phone, knowing only lab.sip (the phone's dns_server)
  ip netns exec ph$o /usr/sbin/dnsmasq --keep-in-foreground --listen-address=127.0.0.1 --port=53 --bind-interfaces \
    --no-resolv --no-hosts --host-record=lab.sip,192.0.2.10 --pid-file=/tmp/dnsmasq-ph$o.pid 2>/dev/null &
  echo 1 > /proc/sys/net/ipv6/conf/v$o/disable_ipv6
  # the box's end of the veth gets the proxy's address too: with no address of its own, the kernel signed its ARP
  # requests toward the phone with the droplet's public address (seen 2026-10-30)
  ip addr add 192.0.2.10/32 dev v$o; echo 2 > /proc/sys/net/ipv4/conf/v$o/arp_announce
  ip link set v$o up
  ip route replace 192.0.2.$o/32 dev v$o src 192.0.2.10
  echo 1 > /proc/sys/net/ipv4/conf/v$o/forwarding     # phone-to-phone RTP crosses the box
  iptables -I INPUT -i v$o -j ACCEPT; iptables -I FORWARD -i v$o -j ACCEPT   # ufw drops what is not on lo
  # each phone's traffic once: 2001's whole capture, and 2002's without what it exchanges with 2001 (already there)
  local f=""; [ $o = 22 ] && f="not host 192.0.2.21"
  tcpdump -i v$o -U -s 0 -w captures/$NAME.v$o.pcap $f 2>/dev/null & TCPDS+=($!)
}

phone() {  # phone <user> <octet> <ctrl> <rtp-base> <seconds> [account params]: baresip, on the box (UDP cases)
  local d; d=$(./baresip-phone.sh "$1" "192.0.2.$2" "$3" "$4" "${6:-}")
  sed -i -e "s|^#\(module[[:space:]]*srtp.so\)|\1|" -e "s|^#\(module[[:space:]]*dtls_srtp.so\)|\1|" "$d/config"
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
tlsphone() {  # tlsphone <user> <octet> <ctrl> <rtp-base> <seconds> [account params]: baresip in its namespace,
  # registering over TLS, checking the server's certificate against the lab CA and the name lab.sip. baresip 1.1.0
  # refuses a sips: account ("SIP register failed: Function not implemented"): its TLS account is sip: + transport=tls
  local d; d=$(./baresip-phone.sh "$1" "192.0.2.$2" "$3" "$4" "${6:-}")
  sed -i "s|<sip:$1@lab.sip>|<sip:$1@lab.sip;transport=tls>|" "$d/accounts"
  sed -i -e "s|^#\?sip_cafile.*|sip_cafile\t\t$L/tls/ca.crt|" -e "s|^#\?sip_verify_server.*|sip_verify_server\tyes|" \
         -e "0,/^#dns_server.*/s||dns_server\t\t127.0.0.1:53|" "$d/config"
  grep -E "^(sip_cafile|sip_verify_server|dns_server)" "$d/config" | sed "s/^/$1 config: /" >> captures/$NAME.ctl.log
  sed "s/auth_pass=[^;]*/auth_pass=.../; s/^/$1 account: /" "$d/accounts" >> captures/$NAME.ctl.log
  ip netns exec ph$2 timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
ctl() { sleep "$1"; ./bctl.py "$2" "$3" "${4:-}" >> captures/$NAME.ctl.log 2>&1; }
nsctl() { sleep "$1"; ip netns exec "$2" ./bctl.py "$3" "$4" "${5:-}" >> captures/$NAME.ctl.log 2>&1; }
B1=4401; B2=4402
tlscall() {  # tlscall <dial uri>: 2002 answers, 2001 dials, 6 s of call, 2001 hangs up
  host 21; host 22
  tlsphone 2002 22 $B2 40000 20 ";answermode=auto;answerdelay=1000"
  tlsphone 2001 21 $B1 30000 20; sleep 3
  nsctl 0 ph21 $B1 dial "$1"; nsctl 7 ph21 $B1 hangup; sleep 2
}
S_CLIENT="openssl s_client -connect lab.sip:5061 -bind 192.0.2.21 -CAfile tls/ca.crt -verify_hostname lab.sip"
S_DIAG="openssl s_client -connect lab.sip:5061 -CAfile tls/ca.crt -verify_hostname lab.sip"   # from the box itself

case $CASE in
  tls)  # the checks a student types, then the phones (host() after the checks: s_client binds to 192.0.2.21 on lab21)
        term "$S_CLIENT < /dev/null 2>&1 | sed -n '/^Certificate chain/,/^---/p; /^Verif/p'"
        term "$S_CLIENT -brief < /dev/null"
        term "$S_CLIENT -tls1_2 -brief < /dev/null"
        term "$S_CLIENT -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' -brief < /dev/null"
        term "$S_CLIENT -tls1 -cipher 'DEFAULT:@SECLEVEL=0' -brief < /dev/null"
        term "$S_CLIENT -tls1 -brief < /dev/null"
        sleep 1; tlscall sip:2002@lab.sip ;;
  tlsdebug)
        term "(cat requests/register-tls.sip; sleep 1) | $S_CLIENT -crlf -quiet -no_ign_eof -nocommands -keylogfile tls/keys.log"
        sleep 1; tlscall sip:2002@lab.sip ;;
  tlsdebug12) term "$S_CLIENT -brief < /dev/null"   # the server now offers TLS 1.2 only
        sleep 1; tlscall sip:2002@lab.sip ;;
  sdes|dtls) ENC=srtp-mand; [ $CASE = dtls ] && ENC=dtls_srtp
        phone 2002 22 $B2 40000 20 ";answermode=auto;answerdelay=1000;mediaenc=$ENC"
        phone 2001 21 $B1 30000 20 ";mediaenc=$ENC"; sleep 3
        ctl 0 $B1 dial sip:2002@lab.sip; ctl 8 $B1 hangup; sleep 2 ;;
  mismatch)  # first 2001 requires SRTP and 2002 has none; then 2001 has none and 2002 requires SRTP
        phone 2002 22 $B2 40000 16 ";answermode=auto;answerdelay=1000"
        phone 2001 21 $B1 30000 16 ";mediaenc=srtp-mand"; sleep 3
        ctl 0 $B1 dial sip:2002@lab.sip; ctl 6 $B1 hangup; sleep 4
        pkill -x baresip; sleep 1
        for u in 2001 2002; do mv captures/$NAME.$u.log captures/$NAME.srtp-caller.$u.log; done
        phone 2002 22 $B2 40000 16 ";answermode=auto;answerdelay=1000;mediaenc=srtp-mand"
        phone 2001 21 $B1 30000 16; sleep 3
        ctl 0 $B1 dial sip:2002@lab.sip; ctl 6 $B1 hangup; sleep 3
        pkill -x baresip; sleep 1
        for u in 2001 2002; do mv captures/$NAME.$u.log captures/$NAME.srtp-callee.$u.log; done ;;
  ticket)  # the phones fail; then the diagnosis a support engineer types on the box
        tlscall sip:2002@lab.sip
        term "$SHOWCERT"
        term "$S_DIAG -brief < /dev/null" ;;
  ticketfix)  # the diagnosis, the new certificate, OpenSIPS restarted to load it (see below), then the phones again
        term "$SHOWCERT"
        term "$S_DIAG -brief < /dev/null"
        cert_cmds lab.sip; for c in "${CERT_CMDS[@]}"; do term "$c"; done
        term "$SHOWCERT"
        # tls_mgm:reload reloads only the TLS domains provisioned in a database ("500: DB url not set" for the
        # domains of the cfg file): OpenSIPS is restarted to load the new certificate
        term "sudo opensips-cli -x mi tls_mgm:reload"
        term "sudo pkill -x opensips"; sleep 2
        term "sudo /usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips-restarted.log 2>&1 &"; sleep 3
        term "$S_DIAG -brief < /dev/null"
        tlscall sip:2002@lab.sip ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac

sleep 1; pkill -x baresip 2>/dev/null; sleep 1
for p in "${TCPDS[@]}"; do kill "$p" 2>/dev/null; done; sleep 1; kill $OSIPS 2>/dev/null; pkill -x opensips 2>/dev/null; sleep 1
pkill -f hep_collector.py 2>/dev/null
unhost
P=captures/$NAME.pcap
mergecap -F pcap -w $P captures/$NAME.lo.pcap $(ls captures/$NAME.v2?.pcap 2>/dev/null) && rm -f captures/$NAME.lo.pcap captures/$NAME.v2?.pcap
R="-o rtp.heuristic_rtp:TRUE"
tshark -r $P -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
# the TLS records of every connection (what a capture of a TLS call shows: handshakes, alerts, application data)
tshark -r $P -Y "tcp.port == 5061 and (tls or (tcp.flags.syn == 1 and tcp.flags.ack == 0) or tcp.flags.reset == 1)" -T fields -e frame.number \
  -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol -e _ws.col.Info \
  2>/dev/null > captures/$NAME.tls.txt
[ -s captures/$NAME.tls.txt ] || rm -f captures/$NAME.tls.txt
tshark -r $P $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r $P $R -Y "rtp or srtp or dtls or icmp" -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport \
  -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null > captures/$NAME.media.txt
# the first three packets of each media stream: the RTP header fields and the first 24 payload bytes (PCMU of a 440 Hz
# tone repeats every 160 samples; SRTP payload looks random)
tshark -r $P $R -Y "rtp and not icmp" -T fields -e frame.number -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
  -e _ws.col.Protocol -e rtp.p_type -e rtp.seq -e rtp.payload -e srtp.enc_payload 2>/dev/null | python3 -c '
import sys, collections
seen = collections.Counter()
print("# frame  stream  protocol  payload type  seq  first 24 payload bytes")
for line in sys.stdin:
    n, s, sp, d, dp, proto, pt, seq, pl, enc = (line.rstrip("\n").split("\t") + [""] * 10)[:10]
    k = f"{s}:{sp} -> {d}:{dp}"
    seen[k] += 1
    if seen[k] <= 3:
        data = (pl or enc).replace(":", "")
        print(f"{n:>5}  {k}  {proto}  pt {pt}  seq {seq}  {data[:48]}")
' > captures/$NAME.payload.txt
case $CASE in
  dtls)  # the DTLS handshakes on the media ports: who is client, the use_srtp profiles offered and chosen
    tshark -r $P -Y dtls -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst \
      -e udp.dstport -e _ws.col.Info 2>/dev/null > captures/$NAME.dtls.txt
    echo >> captures/$NAME.dtls.txt
    tshark -r $P -Y "dtls.handshake.type == 1 or dtls.handshake.type == 2" -V 2>/dev/null | awk '
      /^Frame / {print; hello = ""} /Handshake Type: Client Hello/ {hello = "c"} /Handshake Type: Server Hello/ {hello = "s"}
      /Handshake Type|Version: DTLS|Extension: use_srtp|SRTP Protection Profile:/ {print}
      /Cipher Suite: / && hello == "s" {print}' >> captures/$NAME.dtls.txt ;;
esac
python3 pcap_messages.py $P >/dev/null
# certificates (never the keys) and what OpenSSL reads in them
if [ $TLSCASE = yes ]; then
  for c in tls/ca.crt tls/lab.sip-before-renewal.crt tls/lab.sip.crt; do
    [ -f $c ] || continue
    echo "===== $c"; openssl x509 -in $c -noout -text | grep -vE "^\s+([0-9a-f]{2}:)+[0-9a-f]{0,2}$"
  done > captures/$NAME.certs.txt
  cp tls/ca.crt captures/$NAME.ca.crt; cp tls/lab.sip.crt captures/$NAME.lab.sip.crt
  # for TLS cases the SIP comes from the HEP mirror: the same block layout as pcap_messages.py
  grep -q "SIP$\|SIP  correlation" captures/$NAME.hep.txt && python3 - captures/$NAME.hep.txt captures/$NAME.messages.txt <<'EOF'
import re, sys
blocks = open(sys.argv[1]).read().split("===== ")
out = [b for b in blocks if re.match(r"hep \d+ .*  SIP(  correlation .*)?\n", b)]
open(sys.argv[2], "w").write("".join("===== " + b for b in out))
EOF
fi
case $CASE in
  tlsdebug)  # read the capture: opaque, then decrypted with the key log s_client wrote
    cp tls/keys.log captures/$NAME.keys.log
    term "tshark -r captures/$NAME.pcap -Y sip"
    term "tshark -r captures/$NAME.pcap -Y 'tls' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info | head -20"
    term "cut -c1-72 tls/keys.log"
    term "tshark -r captures/$NAME.pcap -o tls.keylog_file:tls/keys.log -Y sip"
    term "tshark -r captures/$NAME.pcap -o tls.keylog_file:tls/keys.log -Y sip -O sip | grep -E '^(Session Initiation|    (Request|Status)-Line|        (Via|From|To|Contact|WWW-Authenticate):)'"
    term "grep -c '^=====' captures/$NAME.hep.txt"
    term "grep '^=====' captures/$NAME.hep.txt"
    term "grep -A14 '^INVITE sip:2002@lab.sip' captures/$NAME.hep.txt"
    term "grep -E 'over TLS|ERROR' captures/$NAME.opensips.log | cut -d' ' -f4-"
    tshark -r $P -o tls.keylog_file:tls/keys.log -Y sip -O sip 2>/dev/null > captures/$NAME.decrypted.txt ;;
  tlsdebug12)  # the server's keys: HEP TLS events + the Client Hello randoms in the capture
    term "cat captures/$NAME.hepkeys.txt"
    term "tshark -r captures/$NAME.pcap -Y 'tls.handshake.type == 1' -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.handshake.random"
    term "python3 hep_keylog.py captures/$NAME.hepkeys.txt captures/$NAME.pcap > captures/$NAME.keys.log"
    term "tshark -r captures/$NAME.pcap -Y sip"
    term "tshark -r captures/$NAME.pcap -o tls.keylog_file:captures/$NAME.keys.log -Y sip"
    tshark -r $P -o tls.keylog_file:captures/$NAME.keys.log -Y sip -O sip 2>/dev/null > captures/$NAME.decrypted.txt ;;
  tls)    term "grep 'over TLS' captures/$NAME.opensips.log | cut -d' ' -f4- | head -4"
          term "grep -h 'TLS/v4' captures/$NAME.2001.log captures/$NAME.2002.log" ;;
  ticket) term "grep -iE 'tls|reg:|call:|session closed' captures/$NAME.2001.log" ;;
esac
# baresip may log the droplet's public address: mask every eth0/eth1 IPv4 in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.*.diff 2>/dev/null
done
chown -R lab:lab captures tls 2>/dev/null
[ -s captures/$NAME.txt ] && grep -v -E "REGISTER|401 Unauth" captures/$NAME.txt
echo "=== tls"; head -40 captures/$NAME.tls.txt 2>/dev/null
echo "=== rtp"; cat captures/$NAME.rtp.txt
