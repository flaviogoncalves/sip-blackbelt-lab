#!/bin/bash
# A baresip phone for call takes: baresip-conf.sh plus a sine tone as the microphone, the received audio into a file,
# RTP ports from <rtp-base>, and a ctrl_tcp port so the take can dial, answer, hold and hang up on cue (bctl.py).
#   baresip-phone.sh <user> <ip> <ctrl-port> <rtp-base> [extra account params, e.g. ";answermode=auto"] [config name]
# The config name (default: the user) lets two phones register the same user from two addresses (forking).
set -u
USER=$1; IP=$2; CTRL=$3; RTP=$4; EXTRA=${5:-}; NAME=${6:-$1}
DIR=$(./baresip-conf.sh "$NAME" "$IP" "$USER" "$USER" "lab-$USER-pass")
C="$DIR/config"
W="[[:space:]]*"
sed -i -e "s|^module${W}alsa.so|#&|" -e "s|^module_app${W}vidloop.so|#&|" \
       -e "s|^#\(module${W}ausine.so\)|\1|" -e "s|^#\(module${W}aufile.so\)|\1|" -e "s|^#\(module_app${W}ctrl_tcp.so\)|\1|" \
       -e "s|^ctrl_tcp_listen.*|ctrl_tcp_listen 127.0.0.1:$CTRL|" \
       -e "s|^audio_player.*|audio_player aufile,$DIR/received.wav|" \
       -e "s|^audio_source.*|audio_source ausine,440|" \
       -e "s|^audio_alert.*|audio_alert aufile,$DIR/alert.wav|" \
       -e "s|^#rtp_ports.*|rtp_ports $RTP-$((RTP + 9))|" "$C"
# ausine only runs at 48 kHz; baresip resamples it to the 8 kHz of G.711
printf 'ausrc_srate 48000\nausrc_channels 1\n' >> "$C"
sed -i "s|regint=3600|regint=3600$EXTRA|" "$DIR/accounts"
echo "$DIR"
