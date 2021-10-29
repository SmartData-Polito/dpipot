# Basic Firewall Setup

# block IPv6
ip6tables -F
ip6tables -X
ip6tables -P OUTPUT ACCEPT

# this is needed to ntp
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -p icmp -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

ip6tables -A INPUT -j DROP
ip6tables -P FORWARD DROP

# clean up IPv4 tables
iptables -F -t filter
iptables -F -t nat
iptables -F -t mangle

iptables -X -t filter
iptables -X -t nat
iptables -X -t mangle

# Turn off forwarding - traffic must pass on via proxy
echo 1 > /proc/sys/net/ipv4/ip_forward

# accept output traffic
iptables  -P OUTPUT ACCEPT

# INPUT rules for managing the node
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A FORWARD -j DROP
iptables -A INPUT -j DROP
