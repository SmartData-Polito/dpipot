#!/bin/bash

set -e

if [ "$#" -ne 4 ]; then
    echo "Illegal number of parameters. Usage:
basic_debian10.sh NAME MAC PASSWORD PATH"
    exit 1
fi

NAME=$1
MAC=$2
PASSWORD=$3
INSTALL_PATH=$4
MAC_NAME=$( echo $MAC | tr ":" "-" )

NAME_FINAL=${NAME}-${MAC_NAME}

mkdir -p $INSTALL_PATH

echo $NAME_FINAL

cat basic_debian10.cfg | sed s/PASSWORD/$PASSWORD/g > /tmp/preseed.cfg

virt-install \
    --name $NAME_FINAL \
    --description $NAME_FINAL \
    --ram 2048 \
    --vcpus 4 \
    --disk path=$INSTALL_PATH/$NAME_FINAL.img,size=50 \
    --os-type linux  \
    --os-variant debian10 \
    --graphics none \
    --mac $MAC \
    --network network='honeynet' \
    --location 'http://deb.debian.org/debian/dists/buster/main/installer-amd64/' \
    --initrd-inject /tmp/preseed.cfg \
    --extra-args="ks=file:/preseed.cfg console=ttyS0"
