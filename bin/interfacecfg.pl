#!/usr/bin/perl
#
# $Header: /tmp/netpass/NetPass/bin/interfacecfg.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 interfacecfg.pl

=head1 SYNOPSIS

 interfacecfg.pl [-c config] [-r 1|2] [-d 1|2]
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -r 1|2         real server number
     -d 1|2         redirector number

=head1 DESCRIPTION

This script will read the C<netpass.conf> file and will produce
a shell script for the designated server type. That shell script
can be executed, or used in a startup script, to bring High Availability
online.

=head1 SEE ALSO

C<netpass.conf>

C<doc/startup/netpass>

C<doc/startup/netpassha>

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: interfacecfg.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

=cut

use strict;

use Carp;
use Getopt::Std;
use lib qw(/opt/netpass/lib);
use NetPass::Config;

my %opts;
my %ifaces;
my $names = {
		'd'	=> "Director",
		'r'	=> "RealServer"
	    }; 
my $rord;

my $VCONFIG	= "/sbin/vconfig";
my $MODPROBE 	= "/sbin/modprobe";
my $IFCONFIG	= "/sbin/ifconfig";
my $ROUTE	= "/sbin/route";
my $HARESOURCES	= "/etc/ha.d/haresources";

getopts('d:r:c:h', \%opts);

Usage() if ($opts{'h'});
Usage() if (!-e $opts{'c'});
	
if (($opts{'r'} > 2 || $opts{'r'} < 1) &&
    ($opts{'d'} > 2 || $opts{'d'} < 1)) {
	Usage();
} 

$rord = ($opts{'r'}) ? 'r' : 'd';

my $cfg = new NetPass::Config($opts{'c'});
my $networks = $cfg->getNetworks();

foreach my $net (@$networks) {
	my @ips                  = getIps($net);
	$ifaces{$net}{'int'}     = $cfg->getInterface($net); 
	$ifaces{$net}{'qvlan'}   = $cfg->quarantineVlan($net);
	$ifaces{$net}{'nqvlan'}  = $cfg->nonquarantineVlan($net);
	$ifaces{$net}{'vip'}	 = $ips[0]; 
	$ifaces{$net}{'d1'}	 = $ips[1]; 
	$ifaces{$net}{'d2'}	 = $ips[2]; 
	$ifaces{$net}{'r1'}	 = $ips[3]; 
	$ifaces{$net}{'r2'}	 = $ips[4]; 
	$ifaces{$net}{'mask'}	 = $ips[5]; 
	$ifaces{$net}{'bcast'}	 = $ips[6]; 
}

print "#!/bin/bash\n";
print "#\n#  LVS Config for ".$names->{$rord}.' '.$opts{$rord}."\n#\n";

print "
# set up tagged interfaces
$MODPROBE 8021q
$IFCONFIG eth1 up

";

foreach (keys %ifaces) {
	print "# $_ network\n";
	print "$VCONFIG add ".$ifaces{$_}{'int'}.' '.$ifaces{$_}{'qvlan'}."\n";
	
	if ($opts{'r'}) {
		print "$IFCONFIG ".$ifaces{$_}{'int'}.'.'.$ifaces{$_}{'qvlan'}.' '.
	       		$ifaces{$_}{$rord.$opts{$rord}}.' broadcast '.$ifaces{$_}{'bcast'}.
	       		' netmask '.$ifaces{$_}{'mask'}." up\n";
	} else {
		print "$IFCONFIG ".$ifaces{$_}{'int'}." 0.0.0.0 up\n";
		print "$IFCONFIG ".$ifaces{$_}{'int'}.'.'.$ifaces{$_}{'qvlan'}." up\n";
	}
	print "$VCONFIG add ".$ifaces{$_}{'int'}.' '.$ifaces{$_}{'nqvlan'}."\n";
	print "$IFCONFIG ".$ifaces{$_}{'int'}.'.'.$ifaces{$_}{'nqvlan'}." up\n\n";
}

if ($opts{'d'}) {
	director(\%ifaces);
} else {
	realserver(\%ifaces);
}

sub realserver () {
	my $ifaces = shift;

	print "# Setup Realserver Loopback interfaces and routes\n\n";

	foreach (keys %$ifaces) {
		print "# $_ network\n";
		my($s, $n) = (split(/\./, $ifaces->{$_}{'vip'}))[2,3];
		print "$IFCONFIG lo:$s.$n ".$ifaces->{$_}{'vip'}.' broadcast '.
		$ifaces->{$_}{'bcast'}." netmask 0xffffffff up\n";
		
		print "$ROUTE add -host ".$ifaces->{$_}{'vip'}." dev lo:$s.$n\n\n";
	}

	print "# 128.205.1.0/24 network\n";
	print "$IFCONFIG lo:1.40 128.205.1.40 broadcast 128.205.1.255 netmask 0xffffffff up\n";
	print "$ROUTE add -host 128.205.1.40 dev lo:1.40\n\n";

	print <<END
# hiding interface lo, will not arp
echo "1" >/proc/sys/net/ipv4/conf/all/hidden
cat       /proc/sys/net/ipv4/conf/all/hidden
echo "1" >/proc/sys/net/ipv4/conf/lo/hidden
cat       /proc/sys/net/ipv4/conf/lo/hidden
END

}

sub director () {

	my $ifaces = shift;

	print "echo \"#     node              func::ip/netmask/interface/broadcast\" > $HARESOURCES\n";
	print "echo \"npr1.cit.buffalo.edu    IPaddr::128.205.1.40/32/eth0/128.205.1.255 \\\\\" >> $HARESOURCES\n";

	foreach (keys %$ifaces) {
		my $n = $ifaces{$_}{'qvlan'};
		print "echo \"			      IPaddr::".$ifaces->{$_}{'vip'}.
		      "/32/eth1.$n/".$ifaces->{$_}{'bcast'}." \\\\\" >> $HARESOURCES\n";
	}

	print "echo \"                        ldirectord\" >> $HARESOURCES\n\n";

	print <<END
# set ip_forward OFF for vs-dr director (1 on, 0 off)
cat       /proc/sys/net/ipv4/ip_forward
echo "0" >/proc/sys/net/ipv4/ip_forward

# director is not gw for realservers: leave icmp redirects on
echo 'setting icmp redirects (1 on, 0 off) '
echo "1" >/proc/sys/net/ipv4/conf/all/send_redirects
cat       /proc/sys/net/ipv4/conf/all/send_redirects
echo "1" >/proc/sys/net/ipv4/conf/default/send_redirects
cat       /proc/sys/net/ipv4/conf/default/send_redirects
echo "1" >/proc/sys/net/ipv4/conf/eth0/send_redirects
cat       /proc/sys/net/ipv4/conf/eth0/send_redirects

# start heartbeat
/etc/init.d/heartbeat stop
/etc/init.d/heartbeat start

END
}

sub Usage () {
	print "Usage: $0 <[-d director] | [-r realserver]> <-c conf file>\n";
	exit 0;
}

sub ip2int {
	my $i = shift;

	if ($i !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
		die Carp::longmess("ip2int: \"$i\" doesnt look like an ip address to me");
	}

	my @o = split(/\./, $i);
	return ( ($o[0] << 24) |
		 ($o[1] << 16) |
		 ($o[2] <<  8) |
		 ($o[3]      ) );
}

sub int2ip {
	my $i = shift;
	my @o;

	$o[0] = ($i & 0xff000000) >> 24;
	$o[1] = ($i & 0x00ff0000) >> 16;
	$o[2] = ($i & 0x0000ff00) >> 8;
	$o[3] =  $i & 0x000000ff;

	return(join('.', @o));
}

sub getIps () {

	my($ip, $mask) = split(/\//, shift);
	my $m;
	my $i;
	my $s;
	my $b;
	my $vip;
	my $d1;
	my $d2;
	my $r1;
	my $r2;

	my @cidr_to_int = (
		0x00000000, #/0
		0x80000000, #/1
		0xc0000000, #/2
		0xe0000000, #/3
		0xf0000000, #/4
		0xf8000000, #/5
		0xfc000000, #/6
		0xfe000000, #/7
		0xff000000, #/8
		0xff800000, #/9
		0xffc00000, #/10
		0xffe00000, #/11
		0xfff00000, #/12
		0xfff80000, #/13
		0xfffc0000, #/14
		0xfffe0000, #/15
		0xffff0000, #/16
		0xffff8000, #/17
		0xffffc000, #/18
		0xffffe000, #/19
		0xfffff000, #/20
		0xfffff800, #/21
		0xfffffc00, #/22
		0xfffffe00, #/23
		0xffffff00, #/24
		0xffffff80, #/25
		0xffffffc0, #/26
		0xffffffe0, #/27
		0xfffffff0, #/28
		0xfffffff8, #/29
		0xfffffffc, #/30
		0xfffffffe, #/31
		0xffffffff  #/32
	);

        if ($mask =~ /^\d+$/) { # /24
                die Carp::longmess("cidr bit field must be between 1 and 32")
                if ( $mask < 1 || $mask > 32 );
                $m = $cidr_to_int[$mask];
        } else { #/255.255.255.0
                $m = ip2int($mask);
        }

	$i = ip2int($ip);


	$b   =   $i | ~$m;	
	$vip =  ($i | ~$m) - 1;
	$d1  =  ($i | ~$m) - 2;
	$d2  =  ($i | ~$m) - 3;
	$r1  =  ($i | ~$m) - 4;
	$r2  =  ($i | ~$m) - 5;

	return(int2ip($vip),
	       int2ip($d1),
	       int2ip($d2),
	       int2ip($r1),
	       int2ip($r2),
	       int2ip($m),
	       int2ip($b));
}
