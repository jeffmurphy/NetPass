#!/bin/sh 

R="http://foobar.cit.buffalo.edu/netpass/ttt/RHAS4";

mkdir /tmp/npipvs.$$
cd /tmp/npipvs.$$
echo "Working directory: /tmp/npipvs.$$ "

for i in Config.pm \
	heartbeat-1.2.3-1.i386.rpm \
	heartbeat-ldirectord-1.2.3-1.i386.rpm \
	heartbeat-pils-1.2.3-1.i386.rpm \
	heartbeat-stonith-1.2.3-1.i386.rpm \
	ipvsadm-1.21-10.i386.rpm \
	libnet-1.1.2.1-2.i386.rpm ; do 

	rm -f $i
	wget "$R/$i"
done

rpm -iv libnet-1.1.2.1-2.i386.rpm
mkdir -p /var/cache/cpan/build /var/cache/cpan/sources
unset DISPLAY
up2date --nox -i glib-devel openssl-devel libnet   perl-CPAN
cp Config.pm /usr/lib/perl5/5.8.0/CPAN/Config.pm
cat <<EOF

Using CPAN to install some perl modules. If CPAN asks whether
you want to install dependencies, answer "y" (yes).

EOF
sleep 5

echo "install Bundle::CPAN"      | perl -MCPAN -e shell
echo "install Mail::IMAPClient"  | perl -MCPAN -e shell
echo "force install Net::SSLeay" | perl -MCPAN -e shell
echo "install Net::LDAP"         | perl -MCPAN -e shell

rpm -iv heartbeat*.rpm ipvsadm*.rpm

cat <<EOF >>/etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.eth0.send_redirects = 1
EOF

/sbin/ipvsadm-save > /etc/sysconfig/ipvsadm
chkconfig --level 345 ipvsadm on

echo "install Parse::RecDescent" | perl -MCPAN -e shell

up2date --nox -i perl-Digest-HMAC

exit 0
