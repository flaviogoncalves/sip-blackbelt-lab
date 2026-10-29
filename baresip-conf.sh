#!/bin/bash
# Make a baresip config dir bound to one lab address.
#   baresip-conf.sh <name> <ip> <aor-user> <auth-user> <password> [domain]
# The contact is the account's AOR user at <ip>:5060; the registrar sees that Contact and the AOR.
set -u
NAME=$1; IP=$2; USER=$3; AUTH=$4; PASS=$5; DOMAIN=${6:-lab.sip}
DIR=/tmp/baresip-$NAME
rm -rf "$DIR"; mkdir -p "$DIR"
baresip -f "$DIR" -t 1 >/dev/null 2>&1 || true
sed -i "s|^#sip_listen.*|sip_listen $IP:5060|" "$DIR/config"
# its own interface (net.sh: lab21/lab22/lab23), or baresip takes the droplet's public address for logs, SDP and RTP
sed -i "s|^#net_interface.*|net_interface lab${IP##*.}|" "$DIR/config"
echo "<sip:$USER@$DOMAIN>;auth_user=$AUTH;auth_pass=$PASS;regint=3600" > "$DIR/accounts"
echo "$DIR"
