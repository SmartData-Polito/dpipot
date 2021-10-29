# SmartPot

SmartPot orchestrates honeypot systems, steering traffic to diverse backends based on flexible rules. SmartPot includes:

- Flexible steering of traffic to backend systems (built on top of `iptables` rules).
- Layer4 Responder: a responder that opens TCP connections and saves the first packet with payload in each flow.
- DPIPot: a responder that forwards traffic to backend systems after performing DPI classification. Flexible selection of the backend is possible using the DPI classification labels.

Backend systems can be any real systems deployed in a virtual machine, or other honeypots.

The current SmartPot installation relies on third-party state-of-the-art honeypot systems that are organized and delivered by the **TPot project** (see http://github.security.telekom.com/2020/08/honeypot-tpot-20.06-released.html).

TPot and the other honeypots are deployed in a virtual machine for security purposes.

## Installation script

To install it run `make`. Eventually, edit `Makefile` to add a `PREFIX` where files are installed.

To clean it up, run `make distclean`.

