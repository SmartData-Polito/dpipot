#!/bin/bash

set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$#" -ne 1 ]; then
    echo "Missing PREFIX parameter. Usage: install.sh PREFIX"
    exit 1
fi

# Install needed tools
apt install -y pigz

# where things are installed
PREFIX=$1

# create folders
mkdir -p $PREFIX/bin

# capture scripts
cat $DIR/smartpot_capture.service | sed "s|PREFIX|$PREFIX|g" > /lib/systemd/system/smartpot_capture.service
cp $DIR/capture.sh $PREFIX/bin/capture.sh

# permissions
chmod 555 $PREFIX/bin/capture.sh

# reload systemd daemon
systemctl daemon-reload
systemctl enable smartpot_capture.service
systemctl stop smartpot_capture.service
systemctl start smartpot_capture.service
