#!/bin/sh 

R="http://foobar.cit.buffalo.edu/netpass/ttt/RHAS4";
BD=`dirname "$0"`

mkdir /tmp/npipvs.$$
cd /tmp/npipvs.$$
echo "Working directory: /tmp/npipvs.$$ "

for i in Config.pm \
	heartbeat-1.2.3-1.i386.rpm \
	heartbeat-ldirectord-1.2.3-1.i386.rpm \
	heartbeat-pils-1.2.3-1.i386.rpm \
	heartbeat-stonith-1.2.3-1.i386.rpm \
	ipvsadm-1.24-5.i386.rpm \
	libnet-1.1.2.1-2.i386.rpm ; do 

	rm -f $i
	wget "$R/$i"
done

rpm -iv libnet-1.1.2.1-2.i386.rpm
mkdir -p /var/cache/cpan/build /var/cache/cpan/sources
unset DISPLAY
up2date --nox -i glib-devel openssl-devel libnet   perl-CPAN gcc flex bison
# 5.8.5 = RH4
cp Config.pm /usr/lib/perl5/5.8.5/CPAN/Config.pm
cat <<EOF

Using CPAN to install some perl modules. If CPAN asks whether
you want to install dependencies, answer "y" (yes).

EOF
sleep 5

for i in Bundle::CPAN Mail::IMAPClient ExtUtils::AutoInstall Convert::ASN1 Authen::SASL \
Digest::MD5 URI::ldap IO::Socket::SSL XML::SAX::Base MIME::Base64 ; do 
	echo "install " $i | perl -MCPAN -e shell
done

echo "force install Net::SSLeay" | perl -MCPAN -e shell
echo "install Net::LDAP"         | perl -MCPAN -e shell

rpm -iv heartbeat*.rpm ipvsadm*.rpm

cat <<EOF >>/etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.eth0.send_redirects = 1
EOF

cat <<EOF >>/etc/modprobe.conf
#  512 MB RAM
options ip_conntrack hashsize=1048576
# 1024 MB RAM
#options ip_conntrack hashsize=2097152
# 2048 MB RAM
#options ip_conntrack hashsize=4194304
EOF

/sbin/ipvsadm-save > /etc/sysconfig/ipvsadm
chkconfig --level 345 ipvsadm on

echo "install Parse::RecDescent" | perl -MCPAN -e shell

up2date --nox -i perl-Digest-HMAC

cat <<EOF >>/etc/syslog.conf
local0.*        /var/log/ha.log
EOF

cp /dev/null /var/log/ha.log
/etc/init.d/syslog restart
cp ${BD}/iptables-lvs.sh /etc/iptables.sh

cat <<EOF

Edit /etc/modprobe.conf and adjust the hashsize line according to
how much memory this system has.

Edit /etc/iptables.sh and adjust the local system rules section
and then execute:

   # /etc/iptables.sh
   # /etc/init.d/iptables save

to make the rules active.

EOF

exit 0
