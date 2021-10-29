#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Missing PREFIX parameter. Usage: honeypot.sh PREFIX"
    exit 1
fi

# where things are installed
PREFIX=$1

# virtual backend network
NETNAME=$(cat $PREFIX/etc/virsh.xml | grep -oPm1 "(?<=<name>)[^<]+")

# restart the firewall
$PREFIX/bin/firewall.sh

# stop virtual machines and destroy the virtual network
VMS=$( virsh list | tail -n +3 | head -n -1 | awk '{ print $2; }' )
for m in $VMS ; do
    virsh shutdown "$m"
done
virsh net-destroy $NETNAME

# start services relying on iptables
systemctl restart libvirtd

# recreate the virtual network and restart the VMs
virsh net-define $PREFIX/etc/virsh.xml
virsh net-start $NETNAME
virsh net-autostart $NETNAME

# honeypot IPs are NOT assigned to the localhost
iptables -t filter -N chain-honeypot-forward
iptables -t filter -I FORWARD 1 -j chain-honeypot-forward
iptables -t nat    -N chain-honeypot-prerouting
iptables -t nat    -I PREROUTING 1 -j chain-honeypot-prerouting

# honeypot IPs are assigned to the localhost
iptables -t filter -N chain-honeypot-input
iptables -t filter -I INPUT 1 -j chain-honeypot-input
iptables -t nat    -N chain-honeypot-output
iptables -t nat    -I OUTPUT 1 -j chain-honeypot-output

sleep 30
for m in $VMS ; do
    virsh start "$m"
done

# Start the manager listener
$PREFIX/bin/manager.py -c $PREFIX/etc/honeypot.yml -l $PREFIX/log/
