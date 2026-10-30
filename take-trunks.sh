#!/bin/bash
# sip-lab takes for section 6 part A (SIP trunks, caller ID, numbers and ENUM, STIR/SHAKEN, toll fraud, interop checks).
# Two OpenSIPS instances on the box: the lab's proxy (lab.cfg, 192.0.2.10, domain lab.sip) plays the customer's
# proxy/SBC; "the carrier" (opensips/carrier.cfg, 192.0.2.40, domain carrier.example) is a second instance with its own
# rules (IP trunk by address, registration trunk by digest, caller-ID policy). Everything is lab-local and fictitious:
# no real carrier, no real ENUM tree, no real STIR/SHAKEN certificate authority.
#   sudo ./take-trunks.sh <case> <name>
# Cases (lesson): trunkreg trunkip trunkfail (6.1), callerid (6.2), numbers (6.3), stir (6.4), fraud fraudrl fraudpike (6.5),
# interop (6.6), ticket403 ticket403fix (6.7), ticketfraud ticketfraudfix (6.8).
# Numbers (Ofcom ranges kept for drama, fictitious): the customer "acme" holds +44 20 7946 0100-0199 (2001 = 0101,
# 2002 = 0102, 2003 = 0103, main number 0100); the far end is +44 161 496 0142 (Manchester); premium and international
# destinations are +44 909 879 0xxx, +882 and +979 (international premium rate).
# Addresses: proxy 192.0.2.10; phones 2001-2003 = 192.0.2.21-.23; added for the take (removed after): the carrier
# 192.0.2.40, its second SBC 192.0.2.41 (dropped by iptables: a dead trunk), the terminating network's SBC 192.0.2.45
# (STIR/SHAKEN verifier, opensips/verifier.cfg), the far end 192.0.2.50 (SIPp: the rest of the telephone network), the
# office PBX 192.0.2.30, the lab DNS server 192.0.2.53 (dnsmasq), another network's gateway or an unknown address
# 192.0.2.66, an attacker 198.51.100.66.
# Each case writes captures/<name>.pcap (SIP, RTP, DNS and ICMP on lo), .txt (SIP summary), .messages.txt
# (pcap_messages.py), .rtp.txt, .media.txt, the logs of every element (opensips = our proxy, carrier, SIPp: <tag>.log
# and <tag>.msg.log), .cfg.diff / .carrier.cfg.diff when a cfg changes, and per case .mi.txt (MI output), .dns.txt,
# .passport.txt, .cdr.txt, .terminal.txt. Leaves nothing running and lab.cfg untouched.
set -u
CASE=$1; NAME=$2
cd "$(dirname "$0")"; mkdir -p captures
./net.sh >/dev/null
pkill -x opensips 2>/dev/null; pkill -x baresip 2>/dev/null; pkill -x sipp 2>/dev/null; pkill -f 'dnsmasq.*192.0.2.53' 2>/dev/null
sleep 1
mkdir -p /run/opensips
S=scenarios
B3=4403
ADDRS=()   # addresses this take added to lab0
rm -f captures/$NAME.*

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
addr() { ip addr add "$1/32" dev lab0 2>/dev/null; ADDRS+=("$1"); }

# db_text tables: /tmp/lab-trunk for our proxy, /tmp/lab-carrier for the carrier (from the packaged empty tables)
DB=/tmp/lab-trunk; CDB=/tmp/lab-carrier
rm -rf $DB $CDB /tmp/lab-acc; cp -r /usr/share/opensips/dbtext/opensips $DB; cp -r /usr/share/opensips/dbtext/opensips $CDB
row() { printf '%s\n' "$2" >> "$1"; }   # row <table file> <line>: db_text separates columns with ':' (escaped \:)
# the carrier's address table: group 1 = the customer's SBC (IP trunk), group 2 = the far end (the rest of the network)
row $CDB/address '1:1:192.0.2.10:32:0:any::acme SBC (IP trunk)'
row $CDB/address '2:2:192.0.2.50:32:0:any::the far end (interconnect)'

addr 192.0.2.40; addr 192.0.2.50

# ---- our proxy: the trunk side, inserted into lab.cfg ----
AUTH=$'\tif ($fd == "lab.sip") {\n'
RELAY=$'\tt_relay();\n}\n\n# the lab\'s users'
MODS=$'loadmodule "proto_udp.so"\n'
mods() { edit "$MODS" "$MODS"$'\n'"$1"; }   # mods <lines>: load more modules after proto_udp
routes() { edit $'\n# the lab\'s users' "$1"$'\n# the lab\'s users'; }
users() {  # users <user:password>...: extra lab users
  local up lines=""
  for up in "$@"; do lines+=$'\t\tcase "'${up%%:*}$'": $avp(passspec) = "'${up#*:}$'"; break;\n'; done
  edit $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n' \
       $'\t\tcase "2003": $avp(passspec) = "lab-2003-pass"; break;\n'"$lines"
}
TRUNK_ARM=$'\t# section 6: a call from the carrier to one of our numbers goes to the extension that owns it\n\tif ($si == "192.0.2.40" && $rU =~ "^[+]4420794601[0-9][0-9]$") {\n\t\troute(inbound);\n\t\texit;\n\t}\n\t# section 6: a call to a telephone number leaves through the carrier trunk\n\tif (is_method("INVITE") && $rU =~ "^[+0-9][-+0-9.()]{6,}$") {\n\t\troute(outbound);\n\t\texit;\n\t}\n\n'
OUT_AUTH=$'\t# every call to the trunk is authenticated, whatever its From says\n\troute(credentials);\n\tif (!pv_proxy_authorize("lab.sip")) {\n\t\tproxy_challenge("lab.sip", "auth", $var(algs));\n\t\texit;\n\t}\n\tconsume_credentials();\n'
OUT_SEND=$'\t$du = "sip:192.0.2.40:5060";   # the carrier (IP trunk)\n\tt_relay();\n'
DID_MAP=$'\tswitch ($au) {\n\t\tcase "2001": $var(did) = "+442079460101"; $var(name) = "Alice"; break;\n\t\tcase "2002": $var(did) = "+442079460102"; $var(name) = "Bob"; break;\n\t\tcase "2003": $var(did) = "+442079460103"; $var(name) = "Carol"; break;\n\t\tdefault: $var(did) = "+442079460100"; $var(name) = "Acme"; break;\n\t}\n'
TRUNK_ROUTES=$'\n# section 6: a call from the carrier to one of our numbers (+44 20 7946 0101 = 2001, 0102 = 2002, 0103 = 2003)\nroute[inbound] {\n\t$var(did) = $rU;\n\t$ru = "sip:20" + $(rU{s.substr,-2,0}) + "@lab.sip";\n\txlog("L_NOTICE", "inbound: $var(did) is $ru\\n");\n\trecord_route();\n\tif (!lookup("location")) {\n\t\tsend_reply(404, "Not Found");\n\t\texit;\n\t}\n\tt_relay();\n}\n\n# section 6: a call to a telephone number, out through the carrier\nroute[outbound] {\n'"$OUT_AUTH"$'\troute(caller_id);\n\t$rd = "carrier.example";   # the Request-URI in the carrier domain\n\trecord_route();\n'"$OUT_SEND"$'}\n\n# section 6: the caller ID this proxy asserts for the authenticated user (RFC 3325): its number in the trunk\'s range.\n# A P-Asserted-Identity or P-Preferred-Identity written by the phone is not trusted: removed.\nroute[caller_id] {\n'"$DID_MAP"$'\tremove_hf("P-Preferred-Identity");\n\tremove_hf("P-Asserted-Identity");\n\tappend_hf("P-Asserted-Identity: \\"$var(name)\\" <sip:$var(did)@lab.sip;user=phone>\\r\\n");\n}\n'
trunk() { edit "$AUTH" "$TRUNK_ARM$AUTH"; routes "$TRUNK_ROUTES"; }

# ---- SIPp helpers ----
sipp_reg() {  # sipp_reg <user> <ip>
  sipp 192.0.2.10:5060 -sf $S/reg.xml -s "$1" -auth_uri lab.sip -au "$1" -ap "lab-$1-pass" -i "$2" -p 5060 -m 1 \
    -timeout 10s -timeout_error -nostdin > /dev/null 2>&1 || echo "reg $1 failed"
}
far() {  # far <scenario> <seconds> <log tag> [sipp options]: the far end at 192.0.2.50 (SIPp, every call that comes)
  local sc=$1 t=$2 tag=$3; shift 3
  timeout "$t" sipp -sf $S/$sc -s far -i 192.0.2.50 -p 5060 -mp 6000 -nostdin -trace_msg \
    -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 &
}
uac() {  # uac <scenario> <seconds> <log tag> <user> <ip[:port]> [sipp options]: a SIPp caller through our proxy
  local sc=$1 t=$2 tag=$3 u=$4 ip=${5%:*} port=5060; [[ $5 == *:* ]] && port=${5#*:}; shift 5
  timeout "$t" sipp 192.0.2.10:5060 -sf $S/$sc -s "$u" -au "$u" -ap "lab-$u-pass" -i "$ip" -p $port -mp 6100 -m 1 \
    -timeout "${t}s" -nostdin -trace_msg -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 \
    || echo "$tag: sipp ended with an error"
}
direct() {  # direct <target ip> <seconds> <log tag> <from ip[:port]> <callee> <domain> <caller> [sipp options]
  local to=$1 t=$2 tag=$3 ip=${4%:*} port=5060 callee=$5 dom=$6 caller=$7; [[ $4 == *:* ]] && port=${4#*:}; shift 7
  timeout "$t" sipp "$to:5060" -sf $S/direct-call.xml -i "$ip" -p $port -mp 6200 -m 1 -set callee "$callee" \
    -set domain "$dom" -set caller "$caller" -timeout "${t}s" -nostdin -trace_msg \
    -message_file captures/$NAME.$tag.msg.log "$@" > captures/$NAME.$tag.log 2>&1 || echo "$tag: sipp ended with an error"
}
mi() {  # mi <proxy|carrier> <command> [args]: an MI command, its output appended to <name>.mi.txt
  local who=$1 fifo=/run/opensips/opensips_fifo; shift
  [ "$who" = carrier ] && fifo=/run/opensips/carrier_fifo
  { echo "## $(date +%T) $who: opensips-cli -x mi $*"
    opensips-cli -o fifo_file=$fifo -x mi "$@" 2>&1 | sed "s/\x1b\[[0-9;]*m//g"; echo; } >> captures/$NAME.mi.txt
}

phone() {  # phone <user> <ip> <ctrl> <rtp-base> <seconds>: a registered baresip phone of the customer, PCMU only
  local d; d=$(./baresip-phone.sh "$1" "$2" "$3" "$4" ";audio_codecs=PCMU/8000/1")
  timeout "$5" baresip -f "$d" -t "$5" -s > captures/$NAME.$1.log 2>&1 &
}
far_phone() {  # far_phone <seconds>: baresip at 192.0.2.23 as the called person's phone (+44 161 496 0142) on the far
  # network, reached at its contact sip:farphone@192.0.2.23 (baresip finds its account by the Request-URI user and
  # did not match a user written +44...): no registration, answers at once; its log says who it thinks is calling
  local d; d=$(./baresip-phone.sh farphone 192.0.2.23 $B3 50000 ";answermode=auto" far)
  sed -i -e 's|@lab.sip>|@carrier.example>|' -e 's|regint=3600|regint=0|' "$d/accounts"
  timeout "$1" baresip -f "$d" -t "$1" -s > captures/$NAME.farphone.log 2>&1 &
}

stir_certs() {  # a lab CA and the carrier's signing certificate (EC P-256 for ES256, TNAuthList with the fictitious
  # SPC 1234), in /tmp/lab-stir; lab-only, valid 30 days, never published anywhere
  local D=/tmp/lab-stir; rm -rf $D; mkdir -p $D
  openssl ecparam -name prime256v1 -genkey -noout -out $D/ca.key
  openssl req -x509 -new -key $D/ca.key -subj "/CN=sip-lab STI-CA (lab only)" -days 30 -out $D/ca.pem
  openssl ecparam -name prime256v1 -genkey -noout -out $D/sp.key
  openssl req -new -key $D/sp.key -subj "/CN=SHAKEN 1234 carrier.example (lab only)" -out $D/sp.csr
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n1.3.6.1.5.5.7.1.26=DER:3008A006160431323334\n' > $D/ext.cnf
  openssl x509 -req -in $D/sp.csr -CA $D/ca.pem -CAkey $D/ca.key -CAcreateserial -days 30 -extfile $D/ext.cnf \
    -out $D/sp.pem 2>/dev/null
}
pemstr() { awk '{printf "%s\\n", $0}' "$1"; }   # a PEM file as one OpenSIPS string (\n escapes)

# ---- the cases' changes ----
CARRIER=1   # the carrier runs in every case
case $CASE in
  # RFC 3261 10: the trunk registers to the carrier (uac_registrant: REGISTER, 401, REGISTER with credentials, 200);
  # the carrier challenges its calls (407), answered by uac_auth; its From is the number at carrier.example (the
  # carrier's rule for a registration trunk); a call from the far end to 2002's number comes back through the
  # registered contact. The carrier has no IP trunk for 192.0.2.10 in this case.
  trunkreg)
    sed -i '/acme SBC/d' $CDB/address
    edit 'modparam("rr", "append_fromtag", 0)' 'modparam("rr", "append_fromtag", 1)   # uac_replace_from restores From by it'
    row $DB/registrant '1:sip\:carrier.example:sip\:192.0.2.40\:5060:sip\:acme-trunk@carrier.example::acme-trunk:lab-trunk-pass:sip\:acme-trunk@192.0.2.10\:5060::120:::0'
    trunk
    mods $'# section 6: the registration trunk: the REGISTER to the carrier (uac_registrant, table "registrant" in\n# /tmp/lab-trunk) and the answer to the carrier\'s digest challenges (uac_auth, uac)\nloadmodule "db_text.so"\nloadmodule "dialog.so"\nloadmodule "uac_auth.so"\nmodparam("uac_auth", "credential", "acme-trunk:carrier.example:lab-trunk-pass")\nloadmodule "uac.so"\nloadmodule "uac_registrant.so"\nmodparam("uac_registrant", "db_url", "text:///tmp/lab-trunk")\nmodparam("uac_registrant", "timer_interval", 10)\n'
    edit "$OUT_SEND" $'\t# the registration trunk: From = our number at the carrier\'s domain; the carrier will challenge (407)\n\tcreate_dialog();   # uac_auth raises the CSeq: the dialog keeps the in-dialog requests in step\n\tuac_replace_from("$var(name)", "sip:$var(did)@carrier.example");\n\t$du = "sip:192.0.2.40:5060";   # the carrier\n\tt_on_failure("trunk_auth");\n\tt_relay();\n'
    routes $'\n# section 6: the carrier challenged the call: answer with the trunk\'s credentials (uac_auth) and send it again\nfailure_route[trunk_auth] {\n\tif (t_check_status("401|407")) {\n\t\tif (uac_auth()) {\n\t\t\t$du = "sip:192.0.2.40:5060";\n\t\t\tt_relay();\n\t\t}\n\t}\n}\n' ;;
  # an IP trunk: the carrier trusts 192.0.2.10 by address (permissions, group 1). The proxy keeps the trunk's two SBC
  # addresses in a dispatcher set and pings them with OPTIONS every 5 s; 192.0.2.41 never answers (iptables DROP) and
  # is marked down after 2 failed pings. A call goes out through the address that is up; a call from 192.0.2.66, an
  # address the carrier does not know, gets 403.
  trunkip)
    addr 192.0.2.41; addr 192.0.2.66; iptables -I INPUT -d 192.0.2.41 -j DROP
    row $DB/dispatcher '1:1:sip\:192.0.2.40\:5060::0:1:1:0::carrier SBC 1'
    row $DB/dispatcher '2:1:sip\:192.0.2.41\:5060::0:1:1:0::carrier SBC 2'
    trunk
    mods $'# section 6: the carrier\'s two SBC addresses, pinged with OPTIONS (dispatcher, table "dispatcher" in /tmp/lab-trunk)\nloadmodule "db_text.so"\nloadmodule "dispatcher.so"\nmodparam("dispatcher", "db_url", "text:///tmp/lab-trunk")\nmodparam("dispatcher", "ds_ping_method", "OPTIONS")\nmodparam("dispatcher", "ds_ping_from", "sip:sbc@lab.sip")\nmodparam("dispatcher", "ds_ping_interval", 5)\nmodparam("dispatcher", "ds_probing_threshold", 2)\nmodparam("dispatcher", "ds_probing_mode", 1)\n'
    edit "$OUT_SEND" $'\t# the trunk: the first carrier address that is up (dispatcher set 1, algorithm 8: by priority)\n\tif (!ds_select_dst(1, 8)) {\n\t\tsend_reply(503, "Service Unavailable");\n\t\texit;\n\t}\n\tt_relay();\n'
    routes $'\n# section 6: a dispatcher destination changed state (a ping failed, or answered again)\nevent_route[E_DISPATCHER_STATUS] {\n\txlog("L_NOTICE", "dispatcher: set $param(group) destination $param(address) is now $param(status)\\n");\n}\n' ;;
  # lesson 6.1, failover: the same dispatcher set, but the FIRST address (192.0.2.40) is the dead one (iptables DROP);
  # the carrier also listens on 192.0.2.41, which is alive. Call 1 starts before the OPTIONS pings have marked .40 down:
  # its INVITE to .40 gets no answer, tm gives up after fr_timeout (5 s, 408 locally), failure_route marks .40 probing
  # and sends the call to the next address (ds_next_dst). Call 2, after the pings, goes straight to .41.
  trunkfail)
    addr 192.0.2.41; iptables -I INPUT -d 192.0.2.40 -j DROP
    cedit $'socket=udp:192.0.2.40:5060\n' $'socket=udp:192.0.2.40:5060\nsocket=udp:192.0.2.41:5060   # lesson 6.1: the carrier\'s second SBC address\n'
    cedit $'\t$du = "sip:192.0.2.50:5060";   # the far end\n' $'\tforce_send_socket("udp:192.0.2.41:5060");   # lesson 6.1: .40 is down in this take, everything leaves from .41\n\t$du = "sip:192.0.2.50:5060";   # the far end\n'
    row $DB/dispatcher '1:1:sip\:192.0.2.40\:5060::0:1:1:0::carrier SBC 1'
    row $DB/dispatcher '2:1:sip\:192.0.2.41\:5060::0:1:1:0::carrier SBC 2'
    trunk
    mods $'# section 6: the carrier\'s two SBC addresses, pinged with OPTIONS (dispatcher, table "dispatcher" in /tmp/lab-trunk)\nloadmodule "db_text.so"\nloadmodule "dispatcher.so"\nmodparam("dispatcher", "db_url", "text:///tmp/lab-trunk")\nmodparam("dispatcher", "ds_ping_method", "OPTIONS")\nmodparam("dispatcher", "ds_ping_from", "sip:sbc@lab.sip")\nmodparam("dispatcher", "ds_ping_interval", 5)\nmodparam("dispatcher", "ds_probing_threshold", 2)\nmodparam("dispatcher", "ds_probing_mode", 1)\n'
    edit "$OUT_SEND" $'\t# the trunk: the first carrier address that is up (dispatcher set 1, algorithm 8: by priority); on no answer or\n\t# a 5xx, the next one (flag f: the other addresses kept for failover; failure_route[trunk_failover])\n\tif (!ds_select_dst(1, 8, "f")) {\n\t\tsend_reply(503, "Service Unavailable");\n\t\texit;\n\t}\n\txlog("L_NOTICE", "trunk: $rU via $du\\n");\n\tt_on_failure("trunk_failover");\n\tt_relay();\n'
    routes $'\n# section 6: a dispatcher destination changed state (a ping failed, or answered again)\nevent_route[E_DISPATCHER_STATUS] {\n\txlog("L_NOTICE", "dispatcher: set $param(group) destination $param(address) is now $param(status)\\n");\n}\n\n# lesson 6.1: the carrier address did not answer (408 from tm) or failed (5xx): mark it, try the next one\nfailure_route[trunk_failover] {\n\tif (t_was_cancelled())\n\t\texit;\n\tif (t_check_status("408|5[0-9][0-9]")) {\n\t\txlog("L_NOTICE", "failover: the carrier address gave $T_reply_code, marking it probing\\n");\n\t\tds_mark_dst("p");\n\t\tif (ds_next_dst()) {\n\t\t\txlog("L_NOTICE", "failover: next carrier address $du\\n");\n\t\t\tt_on_failure("trunk_failover");\n\t\t\tt_relay();\n\t\t}\n\t}\n}\n' ;;
  # RFC 3325 / RFC 3323: the far end is a real phone (baresip, 192.0.2.23, +44 161 496 0142) on a network the carrier
  # does not trust. Call 1: the phone asks for privacy (From Anonymous, Privacy: id, P-Preferred-Identity); our proxy
  # asserts Alice's number (PAI) toward the carrier, which trusts it and removes it toward the far end. Call 2: the
  # phone writes its own (forged) PAI; our proxy replaces it; no Privacy, so the carrier keeps the PAI to the far end.
  callerid)
    cedit $'\t$du = "sip:192.0.2.50:5060";   # the far end\n' $'\t$ru = "sip:farphone@192.0.2.23:5060";   # the far end: the called person\'s phone (baresip), at its contact\n'
    trunk ;;
  # RFC 3966 / RFC 6116: the office PBX (192.0.2.30, trusted by address) dials the same number in five formats; our
  # proxy normalizes each to E.164, asks ENUM (the enum module; the lab DNS server is dnsmasq at 192.0.2.53, holding a
  # NAPTR for +44 161 496 0142 that points to carrier-b.example, another network: the number was ported there) and
  # sends the call straight there; a number with no ENUM record goes by prefix (drouting: +44 and +1 to the carrier);
  # a prefix with no rule gets 404. Our proxy runs in its own mount namespace where /etc/resolv.conf names 192.0.2.53,
  # so no lookup leaves the box.
  numbers)
    addr 192.0.2.30; addr 192.0.2.53
    row $DB/dr_gateways '1:carrier:0:192.0.2.40\:5060:0:::0:0::the carrier (transit)'
    row $DB/dr_rules '1:1:+44::0::carrier:N:::UK numbers via the carrier'
    row $DB/dr_rules '2:1:+1::0::carrier:N:::North American numbers via the carrier'
    trunk
    mods $'# section 6: ENUM lookups (enum) and prefix routing (drouting, tables dr_gateways and dr_rules in /tmp/lab-trunk)\nloadmodule "db_text.so"\nloadmodule "enum.so"\nloadmodule "drouting.so"\nmodparam("drouting", "db_url", "text:///tmp/lab-trunk")\nmodparam("drouting", "extra_prefix_chars", "+")\nmodparam("drouting", "rule_id_avp", "$avp(dr_rule)")\nmodparam("drouting", "rule_prefix_avp", "$avp(dr_prefix)")\nmodparam("drouting", "gw_id_avp", "$avp(dr_gw)")\n'
    edit "$OUT_AUTH" $'\t# the office PBX (192.0.2.30) is trusted by its address: no digest; nobody else calls in this take\n\tif ($si != "192.0.2.30") {\n\t\tsend_reply(403, "Forbidden");\n\t\texit;\n\t}\n'
    edit $'\t$rd = "carrier.example";   # the Request-URI in the carrier domain\n' ''
    edit "$OUT_SEND" $'\t# the number as dialled, normalized to E.164: RFC 3966 visual separators out, then 00 = the international\n\t# prefix, 0 = the national prefix (UK: +44)\n\t$var(n) = $(rU{re.subst,/[-.() ]//g});\n\tif ($var(n) =~ "^00")\n\t\t$var(n) = "+" + $(var(n){s.substr,2,0});\n\telse if ($var(n) =~ "^0")\n\t\t$var(n) = "+44" + $(var(n){s.substr,1,0});\n\telse if (!($var(n) =~ "^[+][0-9]+$")) {\n\t\tsend_reply(484, "Address Incomplete");\n\t\texit;\n\t}\n\txlog("L_NOTICE", "numbers: dialled $ru -> $var(n)\\n");\n\t$ru = "sip:" + $var(n) + "@carrier.example;user=phone";\n\t# ENUM (RFC 6116): has the number a SIP address of its own? Then straight there\n\tif (enum_query("e164.arpa.")) {\n\t\txlog("L_NOTICE", "numbers: ENUM $var(n) -> $ru\\n");\n\t\tt_relay();\n\t\texit;\n\t}\n\t# no ENUM record: by prefix (drouting group 1)\n\tif (!do_routing(1)) {\n\t\txlog("L_NOTICE", "numbers: ENUM none, no prefix rule for $var(n): 404\\n");\n\t\tsend_reply(404, "No Route");\n\t\texit;\n\t}\n\txlog("L_NOTICE", "numbers: ENUM none, $var(n) matched prefix $avp(dr_prefix) (rule $avp(dr_rule)) -> gateway $avp(dr_gw), $ru\\n");\n\tt_relay();\n' ;;
  # RFC 8224 / 8225 / 8588: the carrier is the authentication service (stir_shaken module, opensips-stir-shaken-module
  # 4.0.3 from apt.opensips.org): it signs every call it takes with the lab certificate and an attestation, A for its
  # customer with a number of the customer's range (2001), B for its customer with another number (2002 presents
  # Bob's mobile, +44 7700 900123), C for a call from another network's gateway (192.0.2.66). The terminating
  # network's SBC (opensips/verifier.cfg, 192.0.2.45) verifies each and passes it to the called phone (192.0.2.50);
  # then a robocaller replays call A's Identity and Date onto a call to another number, straight to the verifier.
  stir)
    addr 192.0.2.45; addr 192.0.2.66
    row $CDB/address '3:2:192.0.2.66:32:0:any::another network gateway (interconnect)'
    stir_certs
    trunk
    edit $'\t\tcase "2002": $var(did) = "+442079460102"; $var(name) = "Bob"; break;\n' $'\t\tcase "2002": $var(did) = "+447700900123"; $var(name) = "Bob";   # lesson 6.4: Bob presents his mobile\n\t\t\tbreak;\n'
    cedit $'loadmodule "proto_udp.so"\n' $'loadmodule "proto_udp.so"\nloadmodule "stir_shaken.so"   # lesson 6.4: the authentication service\n'
    cedit $'\t# caller ID: a customer may only assert a number of its own range\n\tif ($var(source) == "customer") {\n\t\tif ($ai == NULL || !($(ai{uri.user}) =~ "^[+]4420794601[0-9][0-9]$")) {\n\t\t\txlog("L_NOTICE", "carrier: customer call with P-Asserted-Identity <$ai>, not in +44 20 7946 0100-0199: 403\\n");\n\t\t\tsend_reply(403, "Forbidden");\n\t\t\texit;\n\t\t}\n\t} else {\n\t\tremove_hf("P-Asserted-Identity");   # not asserted by anyone this carrier trusts\n\t}\n' \
          $'\t# lesson 6.4: the attestation this carrier gives the call (RFC 8588 4): A = its customer, authenticated, with a\n\t# number of the customer\'s range; B = its customer, but a number it cannot vouch for; C = it only knows where the\n\t# call entered its network (another network\'s gateway)\n\tif ($var(source) == "customer") {\n\t\t$var(orig) = $(ai{uri.user});\n\t\t$var(origid) = "5a1c7e2b-0d4f-4b8e-9c3a-6f2e1d0b7a41";   # this customer\'s trunk\n\t\tif ($var(orig) =~ "^[+]4420794601[0-9][0-9]$")\n\t\t\t$var(attest) = "A";\n\t\telse\n\t\t\t$var(attest) = "B";\n\t} else {\n\t\tremove_hf("P-Asserted-Identity");   # not asserted by anyone this carrier trusts\n\t\t$var(orig) = $fU;\n\t\t$var(origid) = "9e4b2d6a-3f1c-4a7e-8b5d-0c2f6e9a1b37";   # the interconnect gateway\n\t\t$var(attest) = "C";\n\t}\n'
    cedit $'\t$du = "sip:192.0.2.50:5060";   # the far end\n' $'\t# lesson 6.4: sign the call (RFC 8224 authentication service): the Identity header carries the PASSporT\n\t$var(cert) = "'"$(pemstr /tmp/lab-stir/sp.pem)"$'";\n\t$var(key) = "'"$(pemstr /tmp/lab-stir/sp.key)"$'";\n\t$var(rc) = stir_shaken_auth($var(attest), $var(origid), $var(cert), $var(key),\n\t\t"https://cert.carrier.example/lab-shaken.pem", $var(orig), $rU);\n\txlog("L_NOTICE", "carrier: signed: attest $var(attest), orig $var(orig), dest $rU, origid $var(origid) (rc $var(rc))\\n");\n\t$du = "sip:192.0.2.45:5060";   # the terminating network\'s SBC (it verifies)\n'
    VCFG=/tmp/lab-verifier.cfg
    cp opensips/verifier.cfg $VCFG
    editf $VCFG '@CA_LIST@' /tmp/lab-stir/ca.pem; editf $VCFG '@CERT@' "$(pemstr /tmp/lab-stir/sp.pem)" ;;
  # lesson 6.5: what a stolen account dials: account 2001 (SIPp at 192.0.2.21, its password known to the attacker) fires
  # a burst of calls to premium and international premium numbers (+882, +979, +44 909 879); the far end answers them
  # all (a premium line earns by the minute). One limit per case:
  # fraud = fraud_detection (profile 1, per user and prefix: calls per minute, concurrent and sequential calls; events
  # E_FRD_WARNING / E_FRD_CRITICAL logged; critical = 403); fraudrl = ratelimit (a pipe per account, 5 new calls per
  # 10 s, TAILDROP; over the limit = 503 + Retry-After); fraudpike = pike (requests per source address: over 8 per
  # 2 s the address is blocked and its requests dropped, no answer at all).
  fraud)
    trunk
    for r in '1:1:+882' '2:1:+979' '3:1:+44909'; do
      row $DB/fraud_detection "$r:00\:00:23\:59:Mon-Sun:2:4:3600:7200:20:40:2:3:3:5"
    done
    mods $'# lesson 6.5: fraud_detection (rules in table fraud_detection, /tmp/lab-trunk); it needs dialog and drouting\nloadmodule "db_text.so"\nloadmodule "dialog.so"\nloadmodule "drouting.so"\nmodparam("drouting", "db_url", "text:///tmp/lab-trunk")\nmodparam("drouting", "extra_prefix_chars", "+")\nloadmodule "fraud_detection.so"\nmodparam("fraud_detection", "db_url", "text:///tmp/lab-trunk")\n'
    edit "$OUT_SEND" $'\t# lesson 6.5: fraud_detection, profile 1 (premium and international premium prefixes)\n\t$var(rc) = check_fraud($au, $rU, 1);\n\tif ($var(rc) == -2) {\n\t\txlog("L_NOTICE", "fraud: $au -> $rU: over a critical threshold: 403\\n");\n\t\tsend_reply(403, "Forbidden");\n\t\texit;\n\t}\n\tif ($var(rc) == -1)\n\t\txlog("L_NOTICE", "fraud: $au -> $rU: over a warning threshold, call allowed\\n");\n'"$OUT_SEND"
    routes $'\n# lesson 6.5: the events fraud_detection raises\nevent_route[E_FRD_WARNING] {\n\txlog("L_NOTICE", "E_FRD_WARNING: user $param(user) called $param(called_number): $param(param) = $param(value), warning threshold $param(threshold) (rule $param(rule_id))\\n");\n}\nevent_route[E_FRD_CRITICAL] {\n\txlog("L_NOTICE", "E_FRD_CRITICAL: user $param(user) called $param(called_number): $param(param) = $param(value), critical threshold $param(threshold) (rule $param(rule_id))\\n");\n}\n' ;;
  fraudrl)
    trunk
    mods $'# lesson 6.5: ratelimit, a pipe per account; the limit counts per timer interval (10 s)\nloadmodule "ratelimit.so"\nmodparam("ratelimit", "timer_interval", 10)\nmodparam("ratelimit", "limit_per_interval", 1)\n'
    edit "$OUT_SEND" $'\t# lesson 6.5: at most 5 new calls per 10 s per account (pipe "calls-<user>", TAILDROP)\n\tif (!rl_check("calls-$au", 5, "TAILDROP")) {\n\t\txlog("L_NOTICE", "ratelimit: $au -> $rU: over 5 calls in 10 s: 503\\n");\n\t\tappend_to_reply("Retry-After: 5\\r\\n");\n\t\tsend_reply(503, "Service Unavailable");\n\t\texit;\n\t}\n'"$OUT_SEND" ;;
  fraudpike)
    trunk
    mods $'# lesson 6.5: pike, requests per source address (8 per 2 s)\nloadmodule "pike.so"\nmodparam("pike", "sampling_time_unit", 2)\nmodparam("pike", "reqs_density_per_unit", 8)\nmodparam("pike", "pike_log_level", 1)\n'
    edit $'\tif (!mf_process_maxfwd_header(10)) {\n' $'\t# lesson 6.5: requests from the phones are counted per source address; a flood is dropped (no answer)\n\tif ($si != "192.0.2.40" && !pike_check_req()) {\n\t\txlog("L_NOTICE", "pike: $rm from $si dropped\\n");\n\t\texit;\n\t}\n\tif (!mf_process_maxfwd_header(10)) {\n' ;;
  # lesson 6.7: "the carrier answers 403 to every outbound call". The planted fault: our proxy asserts the company's
  # main number for every call and it was typed +44 20 7946 0200, outside the trunk's range (0100-0199); the carrier
  # (its caller-ID rule) answers 403 Forbidden. ticket403fix: +44 20 7946 0100. Callers: baresip 2001 and SIPp 2002.
  ticket403|ticket403fix)
    trunk
    MAIN=+442079460200; [ $CASE = ticket403fix ] && MAIN=+442079460100
    edit "$DID_MAP" $'\t# the company\'s main number on every outbound call\n\t$var(did) = "'$MAIN$'";\n\t$var(name) = "Acme";\n' ;;
  # lesson 6.8: "a weekend of calls to premium numbers" (compressed into seconds). Account 2009 has a weak password
  # (1234). An attacker at 198.51.100.66 guesses passwords with REGISTERs (User-Agent friendly-scanner: wrong guesses
  # get 401 again), finds 2009's, then dials premium and international premium numbers through the trunk. acc writes a
  # CDR per call (db_flatstore: text files in /tmp/lab-acc, one line per call, fields separated by |), with who called,
  # what and from which address. ticketfraudfix = the missing limit: the phones may not dial premium or international
  # premium prefixes (a destination block, 403), the same attack otherwise.
  ticketfraud|ticketfraudfix)
    addr 198.51.100.66
    trunk
    users 2009:1234
    mkdir -p /tmp/lab-acc
    mods $'# lesson 6.8: a CDR per call (acc with the dialog module), written by db_flatstore to /tmp/lab-acc/acc_*.log\nloadmodule "dialog.so"\nloadmodule "db_flatstore.so"\nloadmodule "acc.so"\nmodparam("acc", "db_url", "flatstore:/tmp/lab-acc")\nmodparam("acc", "extra_fields", "db: caller; callee; src_ip; user_agent")\n'
    edit $'\t\tif (!pv_www_authorize("lab.sip")) {\n' $'\t\tif (!pv_www_authorize("lab.sip")) {\n\t\t\txlog("L_NOTICE", "register: $tU from $si ($ua): no valid credentials: 401\\n");\n'
    edit $'\t\tif (!save("location"))\n' $'\t\txlog("L_NOTICE", "register: $tU from $si ($ua): registered\\n");\n\t\tif (!save("location"))\n'
    BLOCK=''
    [ $CASE = ticketfraudfix ] && BLOCK=$'\t# lesson 6.8, the fix: the phones may not dial premium or international premium numbers (a destination block)\n\tif ($rU =~ "^[+](882|979|44909)") {\n\t\txlog("L_NOTICE", "blocked: $au from $si -> $rU: premium destination: 403\\n");\n\t\tt_newtran();   # a transaction, so acc logs the refusal\n\t\tsend_reply(403, "Forbidden");\n\t\texit;\n\t}\n'
    edit "$OUT_SEND" $'\t# lesson 6.8: a CDR for every call to the trunk (cdr: answered calls with their duration; failed: refused ones)\n\tdo_accounting("db", "cdr|failed");\n\t$acc_extra(caller) = $au;\n\t$acc_extra(callee) = $rU;\n\t$acc_extra(src_ip) = $si;\n\t$acc_extra(user_agent) = $ua;\n'"$BLOCK$OUT_SEND" ;;
  # lesson 6.6: the checks before a trunk goes live, typed in a terminal (captures/<name>.terminal.txt): SIPp sends
  # one short scenario per check from the customer's SBC address (192.0.2.10, port 5070) straight to the carrier: codecs,
  # DTMF as RFC 4733 events, 100rel, session timers, early media. The far end is a SIPp callee at 192.0.2.50 that the
  # take starts before each check (the carrier's test number; lab plumbing, not typed by the student).
  interop) ;;
  *) echo "unknown case $CASE"; exit 2 ;;
esac
cmp -s $PLAIN $CFG || diff opensips/lab.cfg $CFG > captures/$NAME.cfg.diff
cmp -s opensips/carrier.cfg $CCFG || diff opensips/carrier.cfg $CCFG > captures/$NAME.carrier.cfg.diff
if [ $CASE = stir ]; then   # the diff names the lab key and certificate instead of spelling them out
  editf captures/$NAME.carrier.cfg.diff "$(pemstr /tmp/lab-stir/sp.key)" '<the lab private key: /tmp/lab-stir/sp.key>'
  editf captures/$NAME.carrier.cfg.diff "$(pemstr /tmp/lab-stir/sp.pem)" '<the lab certificate: /tmp/lab-stir/sp.pem>'
fi

tcpdump -i lo -U -s 0 -w captures/$NAME.pcap 'udp or icmp' 2>/dev/null & TCPD=$!; sleep 1
/usr/sbin/opensips -F -f $CCFG -P /run/opensips/carrier.pid > captures/$NAME.carrier.log 2>&1 & COSIPS=$!
VOSIPS=
[ $CASE = stir ] && { /usr/sbin/opensips -F -f $VCFG -P /run/opensips/verifier.pid > captures/$NAME.verifier.log 2>&1 & VOSIPS=$!; }
if [ $CASE = numbers ]; then
  # the lab DNS server: e164.arpa and example answered here only (--local: NXDOMAIN for any other name in them, no
  # upstream server at all)
  /usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
    --listen-address=192.0.2.53 --port=53 --local=/e164.arpa/ --local=/example/ \
    --host-record=carrier.example,192.0.2.40 --host-record=carrier-b.example,192.0.2.50 \
    --naptr-record='2.4.1.0.6.9.4.1.6.1.4.4.e164.arpa,100,10,u,E2U+sip,!^.*$!sip:+441614960142@carrier-b.example;user=phone!' \
    --log-queries --log-facility=- > captures/$NAME.dnsmasq.log 2>&1 &
  # our proxy in its own mount namespace: resolv.conf names only 192.0.2.53 and nsswitch.conf resolves hosts by
  # /etc/hosts and DNS only (the box's default asks systemd-resolved, which would send a name it cannot answer upstream)
  echo "nameserver 192.0.2.53" > /tmp/lab-resolv.conf
  sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > /tmp/lab-nsswitch.conf
  unshare -m sh -c "mount --bind /tmp/lab-resolv.conf /etc/resolv.conf && mount --bind /tmp/lab-nsswitch.conf \
    /etc/nsswitch.conf && exec /usr/sbin/opensips -F -f $CFG" \
    > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
else
  /usr/sbin/opensips -F -f $CFG > captures/$NAME.opensips.log 2>&1 & OSIPS=$!; sleep 2
fi

case $CASE in
  trunkreg)
    sleep 10; mi proxy uac_registrant:list; mi carrier usrloc:show_contact location acme-trunk@carrier.example
    sipp_reg 2002 192.0.2.22
    far answer.xml 40 far
    timeout 30 sipp -sf $S/answer.xml -s 2002 -i 192.0.2.22 -p 5060 -mp 6300 -m 1 -nostdin -trace_msg \
      -message_file captures/$NAME.2002.msg.log > captures/$NAME.2002.log 2>&1 &
    sleep 1
    uac trunk-call.xml 20 2001 2001 192.0.2.21 -set callee +441614960142
    direct 192.0.2.40 15 inbound 192.0.2.50:5062 +442079460102 carrier.example +441614960142
    sleep 1 ;;
  trunkip)
    mi proxy dispatcher:list; sleep 16; mi proxy dispatcher:list
    far answer.xml 30 far; sleep 1
    uac trunk-call.xml 20 2001 2001 192.0.2.21 -set callee +441614960142
    direct 192.0.2.40 10 unknown 192.0.2.66 +441614960142 carrier.example +441134960000
    sleep 1 ;;
  trunkfail)
    far answer.xml 45 far; mi proxy dispatcher:list; sleep 1
    uac trunk-call.xml 25 call1 2001 192.0.2.21 -set callee +441614960142
    sleep 10; mi proxy dispatcher:list
    uac trunk-call.xml 15 call2 2002 192.0.2.22 -set callee +441614960142
    sleep 1 ;;
  callerid)
    far_phone 30; sleep 2
    uac callerid-private.xml 15 private 2001 192.0.2.21 -set callee +441614960142
    sleep 1
    uac callerid-forged.xml 15 forged 2001 192.0.2.21 -set callee +441614960142
    sleep 1 ;;
  numbers)
    far answer.xml 40 far; sleep 1
    for u in 'sip:+441614960142@lab.sip' 'sip:01614960142@lab.sip' 'sip:00441614960142@lab.sip' 'tel:+44-161-496-0142' \
             'sip:+44-161-496-0142@lab.sip;user=phone' 'sip:+441134960000@lab.sip' 'sip:+88213000000@lab.sip'; do
      timeout 10 sipp 192.0.2.10:5060 -sf $S/pbx-call.xml -i 192.0.2.30 -p 5060 -mp 6400 -m 1 -set ruri "$u" -nostdin \
        -trace_msg -message_file captures/$NAME.pbx.msg.log >> captures/$NAME.pbx.log 2>&1 || echo "pbx: $u: sipp error"
    done ;;
  stir)
    far answer.xml 40 far; sleep 1
    uac trunk-call.xml 15 2001 2001 192.0.2.21 -set callee +441614960142                    # A
    uac trunk-call.xml 15 2002 2002 192.0.2.22 -set callee +441614960142                    # B
    direct 192.0.2.40 10 gateway 192.0.2.66 +441614960142 carrier.example +12025550123    # C
    ID=$(grep -m1 '^Identity:' captures/$NAME.far.msg.log | sed 's/^Identity: *//')
    DT=$(grep -m1 '^Date:' captures/$NAME.far.msg.log | sed 's/^Date: *//')
    timeout 10 sipp 192.0.2.45:5060 -sf $S/stir-replay.xml -i 192.0.2.66 -p 5060 -mp 6200 -m 1 -set callee +441614960999 \
      -set domain 192.0.2.45 -set caller +442079460101 -set date "$DT" -set identity "$ID" -nostdin -trace_msg \
      -message_file captures/$NAME.replay.msg.log > captures/$NAME.replay.log 2>&1 || echo "replay: sipp ended with an error"
    sleep 1 ;;
  fraud|fraudrl|fraudpike)
    # the burst: 15 calls, 3 per second, each held 8 s if answered (field0 = number, field1 = ms)
    { echo SEQUENTIAL; for i in 1 2 3 4 5; do
        echo "+8821300000$i;8000"; echo "+9791000000$i;8000"; echo "+44909879000$i;8000"; done; } > captures/$NAME.burst.csv
    far answer.xml 45 far -mp 6000; sleep 1
    timeout 40 sipp 192.0.2.10:5060 -sf $S/fraud-uac.xml -inf captures/$NAME.burst.csv -s 2001 -au 2001 -ap lab-2001-pass \
      -i 192.0.2.21 -p 5060 -mp 6100 -m 15 -r 3 -l 15 -recv_timeout 10000 -timeout 38s -nostdin -trace_msg \
      -message_file captures/$NAME.2001.msg.log -trace_stat -stf captures/$NAME.2001.stat.csv > captures/$NAME.2001.log 2>&1
    sleep 1 ;;
  ticket403|ticket403fix)
    far answer.xml 40 far; sleep 1
    phone 2001 192.0.2.21 4401 30000 25; sleep 3
    ./bctl.py 4401 dial sip:+441614960142@lab.sip >> captures/$NAME.ctl.log 2>&1; sleep 6
    ./bctl.py 4401 hangup >> captures/$NAME.ctl.log 2>&1; sleep 1
    uac trunk-call.xml 15 2002 2002 192.0.2.22 -set callee +441614960142
    sleep 1 ;;
  ticketfraud|ticketfraudfix)
    { echo SEQUENTIAL; for g in 2001:2001 2001:123456 2001:password 2002:2002 2002:1234 2003:2003 2009:2009 2009:password \
        2009:1234; do echo "${g%%:*};[authentication username=${g%%:*} password=${g#*:}]"; done; } > captures/$NAME.guesses.csv
    timeout 20 sipp 192.0.2.10:5060 -sf $S/guess-reg.xml -inf captures/$NAME.guesses.csv -i 198.51.100.66 -p 5060 -m 9 -r 4 \
      -l 1 -timeout 18s -nostdin -trace_msg -message_file captures/$NAME.scan.msg.log > captures/$NAME.scan.log 2>&1
    { echo SEQUENTIAL; for i in 1 2 3 4; do
        echo "+8821300000$i;10000"; echo "+9791000000$i;10000"; echo "+44909879000$i;10000"; done; } > captures/$NAME.calls.csv
    far answer.xml 45 far; sleep 1
    timeout 40 sipp 192.0.2.10:5060 -sf $S/fraud-uac.xml -inf captures/$NAME.calls.csv -s 2009 -au 2009 -ap 1234 \
      -i 198.51.100.66 -p 5060 -mp 6100 -m 12 -r 2 -l 12 -timeout 38s -nostdin -trace_msg \
      -message_file captures/$NAME.attacker.msg.log > captures/$NAME.attacker.log 2>&1
    sleep 1 ;;
  interop)
    T=captures/$NAME.terminal.txt
    term() {  # term <command>: typed as user lab in ~/lab; the prompt, the command and its output go to the terminal file
      printf 'lab@sip-lab:~/lab$ %s\n' "$1" >> $T
      env -i HOME=/home/lab USER=lab LOGNAME=lab PATH=/usr/local/bin:/usr/bin:/bin \
        setpriv --reuid=lab --regid=lab --init-groups bash -c "cd /home/lab/lab && $1" >> $T 2>&1
    }
    check() {  # check <scenario> <far-end scenario> <log> <seconds> [sudo]: the far end waits, the student runs SIPp
      # (with sudo when the scenario plays a pcap: SIPp needs a raw socket for that)
      timeout "$4" sipp -sf $S/$2 -s far -i 192.0.2.50 -p 5060 -mp 6000 -m 1 -nostdin > captures/$NAME.far-$3.log 2>&1 &
      local farpid=$!; sleep 1
      term "${5:+sudo }sipp 192.0.2.40 -sf scenarios/$1 -set callee +441614960142 -i 192.0.2.10 -p 5070 -m 1 -timeout $4s -nostdin -trace_msg -message_file /tmp/$3.log > /dev/null; echo \"sipp exit code \$?\""
      sleep 1; kill $farpid 2>/dev/null; wait $farpid 2>/dev/null
    }
    rm -f /tmp/interop.pcap /tmp/codecs.log /tmp/dtmf.log /tmp/100rel.log /tmp/timer.log /tmp/early.log
    term "sudo timeout 110 tcpdump -i lo -n -U -w /tmp/interop.pcap udp 2>/dev/null &"; sleep 2
    check interop-codecs.xml answer.xml codecs 20
    term "grep -E '^(INVITE sip|SIP/2.0|m=audio|a=rtpmap)' /tmp/codecs.log"
    check interop-dtmf.xml answer.xml dtmf 20 sudo
    term "tshark -r /tmp/interop.pcap -Y rtpevent -T fields -e frame.time_relative -e ip.src -e ip.dst -e rtp.p_type -e rtpevent.event_id -e rtpevent.end_of_event -e rtpevent.duration 2>/dev/null"
    check interop-100rel.xml uas-100rel.xml 100rel 20
    term "grep -E '^(INVITE sip|PRACK sip|SIP/2.0|Supported|Require|RSeq|RAck)' /tmp/100rel.log"
    check interop-timer.xml uas-timer.xml timer 70
    term "grep -E '^(INVITE sip|SIP/2.0|Session-Expires|Min-SE|Require)' /tmp/timer.log"
    check interop-early.xml uas-early.xml early 20
    term "grep -E '^(-{10}|INVITE sip|SIP/2.0|m=audio)' /tmp/early.log"
    term "tshark -r /tmp/interop.pcap -Y 'sip.Status-Code >= 180 && ip.dst == 192.0.2.10' -T fields -e frame.time_relative -e sip.Status-Line 2>/dev/null | tail -n 3"
    term "tshark -r /tmp/interop.pcap -o rtp.heuristic_rtp:TRUE -q -z rtp,streams 2>/dev/null"
    cp /tmp/interop.pcap captures/$NAME.student.pcap 2>/dev/null; cp /tmp/{codecs,dtmf,100rel,timer,early}.log captures/ 2>/dev/null
    for f in codecs dtmf 100rel timer early; do mv captures/$f.log captures/$NAME.$f.msg.log 2>/dev/null; done ;;
esac

sleep 1; pkill -x sipp 2>/dev/null; pkill -x baresip 2>/dev/null
kill $TCPD 2>/dev/null; sleep 1; kill $OSIPS $COSIPS $VOSIPS 2>/dev/null; sleep 1
pkill -f 'dnsmasq.*192.0.2.53' 2>/dev/null
rm -rf /tmp/lab-trunk /tmp/lab-carrier /tmp/baresip-far
iptables -D INPUT -d 192.0.2.41 -j DROP 2>/dev/null; iptables -D INPUT -d 192.0.2.40 -j DROP 2>/dev/null
for a in "${ADDRS[@]}"; do ip addr del "$a/32" dev lab0 2>/dev/null; done
R="-o rtp.heuristic_rtp:TRUE"
tshark -r captures/$NAME.pcap -Y sip -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.txt
tshark -r captures/$NAME.pcap $R -q -z rtp,streams 2>/dev/null > captures/$NAME.rtp.txt
tshark -r captures/$NAME.pcap $R -Y "rtp or rtpevent or icmp" -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type -e _ws.col.Protocol 2>/dev/null > captures/$NAME.media.txt
python3 pcap_messages.py captures/$NAME.pcap >/dev/null
tshark -r captures/$NAME.pcap -Y dns -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info \
  2>/dev/null > captures/$NAME.dns.txt; [ -s captures/$NAME.dns.txt ] || rm -f captures/$NAME.dns.txt
# stir: every Identity header in the capture, decoded (RFC 8225: header and payload are base64url JSON; ES256 signature =
# r || s, 64 bytes), checked again here with the lab certificate (python3-cryptography), then the certificate itself
[ $CASE = stir ] && python3 - captures/$NAME.messages.txt /tmp/lab-stir/sp.pem > captures/$NAME.passport.txt <<'EOF'
import base64, json, re, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
msgs, certfile = sys.argv[1:3]
key = x509.load_pem_x509_certificate(open(certfile, "rb").read()).public_key()
def b64(x):
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
frame = ruri = None
print("# Every INVITE in the capture that carries an Identity header (RFC 8224), decoded. PASSporT = header.payload.signature,")
print("# each base64url (RFC 8225); the signature is ES256 over 'header.payload', checked here again with the lab certificate.")
for line in open(msgs):
    if line.startswith("====="):
        frame = line.strip(); continue
    if line.startswith("INVITE "):
        ruri = line.strip()
    m = re.match(r"Identity: *(.*)", line)
    if not m:
        continue
    token, _, params = m.group(1).strip().partition(";")
    h, p, sig = token.split(".")
    raw = b64(sig)
    try:
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   (h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))
        ok = "valid (the lab certificate's key signed exactly this header.payload)"
    except Exception as e:
        ok = f"INVALID ({type(e).__name__})"
    print(f"\n{frame}\n{ruri}\nIdentity parameters: {params}")
    print("PASSporT header:  " + json.dumps(json.loads(b64(h)), separators=(", ", ": ")))
    print("PASSporT payload: " + json.dumps(json.loads(b64(p)), separators=(", ", ": ")))
    print(f"signature: {len(raw)} bytes, {ok}")
EOF
[ $CASE = stir ] && { echo; echo "# the lab certificate (x5u names it; lab-only, never published by any server)"; \
  openssl x509 -in /tmp/lab-stir/sp.pem -noout -text; } >> captures/$NAME.passport.txt
# ticketfraud: the CDR files, one line per call, in time order
if [[ $CASE == ticketfraud* ]]; then
  { echo "# acc CDRs (db_flatstore, /tmp/lab-acc/acc_<process>.log, joined and sorted by time). Answered calls (cdr):"
    echo "# method|from_tag|to_tag|callid|sip_code|sip_reason|time|caller|callee|src_ip|user_agent|setuptime|created|duration|ms_duration"
    echo "# refused calls (failed) have the same columns, setuptime and durations 0. time = when the call was answered (or"
    echo "# refused), created = its INVITE; setuptime and duration in seconds. Column order as the files have it."
    cat /tmp/lab-acc/acc_*.log 2>/dev/null | sort -t'|' -k7,7n; } > captures/$NAME.cdr.txt
fi
# mask every eth0/eth1 IPv4 (the droplet's public and private addresses) in what this take wrote
for A in $(ip -4 -o addr show | awk '$2 ~ /^eth/ {split($4, a, "/"); print a[1]}'); do
  sed -i "s/${A//./\\.}/203.0.113.10/g" captures/$NAME.*.log captures/$NAME.*txt captures/$NAME.*diff 2>/dev/null
done
rm -rf /tmp/lab-acc /tmp/lab-stir
cat captures/$NAME.txt
