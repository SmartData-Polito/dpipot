#!/bin/bash

set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$#" -ne 1 ]; then
    echo "Missing PREFIX parameter. Usage: install.sh PREFIX"
    exit 1
fi

set +e
systemctl stop smartpot_dpi.service
systemctl stop smartpot_honeypot.service
systemctl stop smartpot_dpipot.service
set -e

# where things are installed
PREFIX=$1

# create folders
mkdir -p $PREFIX/bin
mkdir -p $PREFIX/etc
mkdir -p $PREFIX/log

# Install the virtualization environment
apt install -y libvirt-clients \
                qemu-kvm libvirt-clients \
                libvirt-daemon-system \
                virtinst \
                rsyslog

# Install nDPI and libpcap
apt install -y python3-scapy \
                libpcap-dev \
                libgcrypt20-dev \
                libjson-c-dev \
                expect

apt install python3-pip
pip3 install murmurhash3
pip3 install twisted

# compile the DPI backend
cd $DIR/../dpiclass
make
cp classifier $PREFIX/bin/
cat smartpot_dpi.service | sed "s|PREFIX|$PREFIX|g" > /lib/systemd/system/smartpot_dpi.service
systemctl daemon-reload
systemctl enable smartpot_dpi.service
systemctl start smartpot_dpi.service
make clean
cd -

# copy config files
cp $DIR/etc/honeypot.yml $PREFIX/etc/honeypot.yml
cp $DIR/etc/virsh.xml    $PREFIX/etc/virsh.xml

# copy binary files
cp $DIR/honeypot.sh $PREFIX/bin/honeypot.sh
cp $DIR/*.py        $PREFIX/bin/

# permissions
chmod 555 $PREFIX/bin/*

# Install and start the services
cat $DIR/smartpot_honeypot.service | sed "s|PREFIX|$PREFIX|g" > /lib/systemd/system/smartpot_honeypot.service
cat $DIR/smartpot_dpipot.service | sed "s|PREFIX|$PREFIX|g" > /lib/systemd/system/smartpot_dpipot.service

systemctl daemon-reload
systemctl enable smartpot_honeypot.service
systemctl enable smartpot_dpipot.service
systemctl start smartpot_honeypot.service
systemctl start smartpot_dpipot.service
