#!/bin/bash

# Darknet
DARK="(net 0.0.0.0/0)"
DEV_DARK=wlp2s0

# Honeypot
HONEYPOT="(net 0.0.0.0/0)"
DEV_HONEYPOT=wlp2s0

if [ "$#" -ne 1 ]; then
    echo "Missing PREFIX parameter.

Usage: capture.sh PREFIX

PREFIX - where the PCAPs will be saved.
"
    exit 1
fi


PREFIX=$1
mkdir -p $PREFIX/darknet
mkdir -p $PREFIX/honeypots

$PREFIX/bin/firewall.sh

sudo tcpdump -i $DEV_DARK -nn -tt $DARK -G 3600 -Z root -w $PREFIX/darknet/trace-%Y%m%d_%H-%M-%S_%s.pcap &
P1=$!
sudo tcpdump -i $DEV_HONEYPOT -nn -tt $HONEYPOT -G 3600 -Z root -w $PREFIX/honeypots/trace-%Y%m%d_%H-%M-%S_%s.pcap &
P2=$!
wait $P1 $P2
