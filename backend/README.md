# SmartPot Backend

This folder contains some supporting scripts for the creation of the backend systems. These scripts are not yet integrated into the general installation script. Some manual steps are still needed as described bellow.

## Installation

### Generic backend machine

These instructions apply to the installation of generic Linux machine to support the backends.

- Install a clean Debian virtual machine.

Assuming the general SmartPot installation has been executed already, run:

`sudo ./basic_debian10.sh NAME MAC PASSWORD PATH`

Where:
--NAME      Name of the virtual machine
--MAC       MAC address of the virtual machine
--PASSWORD  Root password
--PATH      Place where the image will be located

NAME and MAC must be in sync with the content of `honeypot/etc/virsh.xml` file, where the DHCP is configured.

Example:

`$ sudo ./basic_debian10.sh honeypot-tpot 00:00:00:00:00:AA my_secret_pass /opt/vms`


### TPot

Run the installation script of TPot. Eventually, edit the file `tpot.conf`
before running the command. In particular, **TPot sends all data to a community repository by default**.
The provided file `tpot.conf` disables that feature.

`./tpot.sh`

