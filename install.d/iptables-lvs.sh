#!/bin/bash


export PATH=/sbin:${PATH}


echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects # Enable bad error message protection.
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses # Log spoofed packets, source routed packets, redirect packets.
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
echo 0 > /proc/sys/net/ipv4/ip_forward


iptables -F INPUT
iptables -F FORWARD
iptables -F OUTPUT

iptables -Z INPUT
iptables -Z FORWARD
iptables -Z OUTPUT

iptables -A INPUT    -j DROP
iptables -A FORWARD  -j DROP
iptables -A OUTPUT   -j DROP

iptables -F PREROUTING -t mangle
iptables -F OUTPUT -t mangle
iptables -F INPUT -t mangle
iptables -F FORWARD -t mangle

iptables -A PREROUTING -t mangle -i eth0 -j RETURN
#iptables -A PREROUTING -t mangle         -j LOG \
#	--log-level 6 --log-prefix 'preroute-marked '

iptables -A PREROUTING -t mangle -p udp --dport 53        -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -p udp --dport 53        -j RETURN

iptables -A PREROUTING -t mangle -p udp --dport 67        -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -p udp --dport 67        -j RETURN

iptables -A PREROUTING -t mangle -p udp --dport 161        -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -p udp --dport 161        -j RETURN

iptables -A PREROUTING -t mangle -p udp --dport 162        -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -p udp --dport 162        -j RETURN

iptables -A PREROUTING -t mangle -p tcp --dport 80        -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -p tcp --dport 80        -j RETURN

iptables -A PREROUTING -t mangle -p tcp --dport 443        -j MARK --set-mark 1
iptables -A PREROUTING -t mangle -p tcp --dport 443        -j RETURN

iptables -A PREROUTING -t mangle        -j DROP

#iptables -A PREROUTING -t mangle         -j MARK --set-mark 1


# local system rules here

iptables -A INPUT -s 128.205.1.0/24 -j ACCEPT
iptables -A INPUT -s 128.205.10.0/24 -j ACCEPT

# end local rules. all else is dropped.

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -f -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -j DROP
iptables -f -A INPUT -j DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -f -A INPUT -i lo -j ACCEPT

iptables -A OUTPUT -s 0/0 -d 0/0 -j ACCEPT
iptables -f -A OUTPUT -s 0/0 -d 0/0 -j ACCEPT

iptables -D INPUT    1
iptables -D FORWARD  1
iptables -D OUTPUT   1

exit 0


