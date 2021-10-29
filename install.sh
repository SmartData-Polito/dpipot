#!/bin/bash

set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$#" -ne 1 ]; then
    echo "Missing PREFIX parameter. Usage: install.sh PREFIX"
    exit 1
fi

VERSION=$(lsb_release -a 2>/dev/null | grep Release | awk '{print $NF}')
if [ "$VERSION" != "unstable" ] && [ "$VERSION" != "20.04" ]; then
    echo "SmartPot expects Ubuntu 20.04 or Debian Unstable"
    exit 1
fi

# where things are installed
PREFIX=$1

# create the folder (needs sudo)
mkdir -p $PREFIX

# move the basic firewall
mkdir -p $PREFIX/bin
cp $DIR/firewall.sh $PREFIX/bin/firewall.sh
chmod 555 $PREFIX/bin/firewall.sh

# install the capture scripts
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. $DIR/capture/install.sh

# install the honeypot systems
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. $DIR/honeypot/install.sh $PREFIX

chmod o+r -R $PREFIX
chmod o+rx $PREFIX
chmod o+rx $PREFIX/bin/*
