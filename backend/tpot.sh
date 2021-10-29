#!/bin/bash

set -e

if [ "$#" -ne 0 ]; then
    echo "Illegal number of parameters. Usage:
tpot.sh"
    exit 1
fi

git clone https://github.com/telekom-security/tpotce
cd tpotce/iso/installer/
cp tpot.conf.dist tpot.conf
./install.sh --type=auto --conf=tpot.conf
