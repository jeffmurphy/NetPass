#!/bin/bash

export PATH=/sbin:${PATH}

echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects # Enable bad error message protection.
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses # Log spoofed packets, source routed packets, redirect packets.
echo 0 > /proc/sys/net/ipv4/conf/all/log_martians
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F INPUT
iptables -F FORWARD
iptables -F OUTPUT

iptables -t nat -F nat_dns_and_log 
iptables -t nat -F denied_https
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -t nat -F OUTPUT 

iptables -t nat -Z PREROUTING
iptables -t nat -Z POSTROUTING
iptables -t nat -Z OUTPUT

iptables -Z INPUT
iptables -Z FORWARD
iptables -Z OUTPUT

iptables -A INPUT    -j DROP
iptables -A FORWARD  -j DROP
iptables -A OUTPUT   -j DROP

iptables -t nat -X denied_https
iptables -t nat -N denied_https
#NB for i in %NETBLOCK% ; do 
#NB     iptables -A INPUT -i eth0 -p tcp -s ! $i --dport 443 \
#NB 	-j LOG --log-level 6 --log-prefix 'https drop '
#NB     iptables -A INPUT -i eth0 -p tcp -s ! $i --dport 443 \
#NB 	-j DROP
#NB done
iptables -t nat -A denied_https -j RETURN

iptables -t nat -X nat_dns_and_log
iptables -t nat -N nat_dns_and_log
iptables -t nat -A nat_dns_and_log -p tcp --dport ! 53 -j RETURN
iptables -t nat -A nat_dns_and_log -p udp --dport ! 53 -j RETURN
##iptables -t nat -A nat_dns_and_log -j LOG --log-level 6 --log-prefix 'nat-dns '
iptables -t nat -A nat_dns_and_log -j ACCEPT -p udp --dport 53
iptables -t nat -A nat_dns_and_log -j ACCEPT -p tcp --dport 53

# Drop Web requests from outside of your address space

#NB for i in %NETBLOCK% ; do 
#NB     iptables -A INPUT -i eth0 -p tcp -s ! $i --dport 80 \
#NB 	-j LOG --log-level 6 --log-prefix 'http drop '
#NB     iptables -A INPUT -i eth0 -p tcp -s ! $i --dport 80 \
#NB 	-j DROP
#NB done


# NETPASS MODS
# 
# 1. source-nat port 53 but only for 128.205.1.2 and 128.205.106.1
# 2. redirect ports 23, 80, 443 to ourselves
# 3. drop all else

iptables -t nat -A PREROUTING -j nat_dns_and_log
iptables -t nat -A PREROUTING -p tcp --dport 443 -j denied_https


iptables -t nat -A PREROUTING -p tcp --dport 443  -j ACCEPT

##iptables -t nat -A PREROUTING -p tcp --dport 80 -j LOG --log-level 6 --log-prefix 'web redirect '

# traffic destined to our webserver is allowed in

#NPVIP iptables -t nat -A PREROUTING -p tcp -d %NPVIP% --dport 80 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d %MYIP% --dport 80 -j ACCEPT

# traffic destined to other webservers is redirected to squid

iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 3128

# allow management traffic into box 

#MGT for i in %MGTDEVS% ; do
#MGT    iptables -t nat -A PREROUTING -j ACCEPT -s $i -p tcp --dport 22
#MGT    iptables -t nat -A PREROUTING -j ACCEPT -s $i -p udp --dport 161
#MGT done

#TRAP for i in %TRAPDEVS% ; do
#TRAP   iptables -t nat -A PREROUTING -j ACCEPT -s $i -p udp --dport 162
#TRAP done


# allow the netpass servers to talk to each other via mysql

#NPS for i in %NETPASSSERVERS% ; do 
#NPS     iptables -t nat -A PREROUTING -j ACCEPT -s $i -p tcp --dport 3306
#NPS done


#### PUT CUSTOM RULES HERE ####
####    SEE BELOW ALSO     ####
#### you'll also need to 
#### add to the INPUT rules

# allow adsm
iptables -t nat -A PREROUTING -p tcp --dport 1500:1505 -s 128.205.7.80/32 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 1500:1505 -s 128.205.7.112/32 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 1500:1505 -s 128.205.106.80/32 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 1500:1505 -s 128.205.106.112/32 -j ACCEPT

#### END CUSTOM RULES HERE ####




iptables -t nat -A PREROUTING -j ACCEPT -p udp --dport 67 #dhcp
iptables -t nat -A PREROUTING -j ACCEPT -p icmp
##iptables -t nat -A PREROUTING -j LOG --log-level 6 --log-prefix 'drop prerouting '
# drop all else
iptables -t nat -A PREROUTING -j DROP





# anything that makes it to the postrouting chain should be NAT'd

iptables -t nat -A POSTROUTING -p udp --dport  443 \
    -j LOG --log-level 6 --log-prefix 'https postroute '
iptables -t nat -A POSTROUTING -p tcp --dport  443 \
    -j LOG --log-level 6 --log-prefix 'https postroute '

iptables -t nat -A POSTROUTING -j MASQUERADE






iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 67 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT      # SQUID

# since the PREROUTING rules already applied source filters,
# we dont have to repeat those filters here

iptables -A INPUT -i eth0 -p udp --dport 161  -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 162  -j ACCEPT
iptables -A INPUT         -p icmp             -j ACCEPT
iptables -A INPUT         -p tcp --dport 22   -j ACCEPT
iptables -A INPUT         -p tcp --dport 123 --sport 123  -j ACCEPT
iptables -A INPUT -p tcp         --dport 3306 -j ACCEPT

#iptables -A INPUT -d 224.0.0.0/4 -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

#### PUT CUSTOM RULES HERE ####
#### cut/paste your PREROUTING rules here and change 
#### PREROUTING to INPUT

# adsm
iptables -A INPUT -p tcp --dport 1500:1505 -s 128.205.7.80/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 1500:1505 -s 128.205.7.112/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 1500:1505 -s 128.205.106.80/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 1500:1505 -s 128.205.106.112/32 -j ACCEPT

#### END CUSTOM RULES HERE ####

# mysql

iptables -A INPUT -d 255.255.255.255/32 -j DROP
# log what we are about to drop
iptables -A INPUT -j LOG --log-level 6 --log-prefix 'dropped input '
# drop everything that didnt already match
iptables -A INPUT -j DROP
iptables -f -A INPUT -j DROP

# enable forwarding  - anything that makes it this far is forwarded

iptables -A FORWARD -m state --state ESTABLISHED,RELATED \
         -j ACCEPT
##iptables -A FORWARD -j LOG --log-level 6 --log-prefix 'forwarded '
iptables -A FORWARD -j ACCEPT
iptables -f -A FORWARD -j ACCEPT

# allow all outbound from local machine

iptables -A OUTPUT -s 0/0 -d 0/0 -j ACCEPT

iptables -D INPUT    1
iptables -D FORWARD  1
iptables -D OUTPUT   1

exit 0


