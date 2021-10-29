#!/bin/bash

set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$#" -ne 1 ]; then
    echo "Missing PREFIX parameter. Usage: clean.sh PREFIX"
    exit 1
fi

# where things are installed
PREFIX=$1

# clean up the firewall rules
if [ -f "$PREFIX/bin/firewall.sh" ]; then
  $PREFIX/bin/firewall.sh
fi

set +e
systemctl stop smartpot_dpi
systemctl stop smartpot_capture
systemctl stop smartpot_honeypot
systemctl disable smartpot_dpi
systemctl disable smartpot_capture
systemctl disable smartpot_honeypot
set -e
rm -rf /lib/systemd/system/smartpot_*
rm -rf /etc/cron.daily/smartpot_move.sh
systemctl daemon-reload
rm -rf "$PREFIX"
