#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/interfacecfg.pl,v 1.12 2005/08/04 06:45:24 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 interfacecfg.pl

=head1 SYNOPSIS

 interfacecfg.pl [-c cstr] [-U dbuser/dbpass] [-r 1|2] [-d 1|2]
     -c cstr        db connect string
     -U user/pass   db user[/pass]
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

$Id: interfacecfg.pl,v 1.12 2005/08/04 06:45:24 jeffmurphy Exp $

=cut

use strict;

use Carp;
use Getopt::Std;
use lib qw(/opt/netpass/lib);
use NetPass;
use Pod::Usage;

sub getIps($);
sub director($);
sub realserver($);
sub getmem();

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

getopts('U:d:r:c:h', \%opts);

pod2usage(2) if ($opts{'h'});

if (exists $opts{'r'} && ($opts{'r'} > 2 || $opts{'r'} < 1)) {
	pod2usage(1);
} 

if (exists $opts{'d'} && ($opts{'d'} > 2 || $opts{'d'} < 1)) {
	pod2usage(1);
}
	
$rord = ($opts{'r'}) ? 'r' : 'd';

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my $networks = $np->cfg->getNetworks();

foreach my $net (@$networks) {
	my @ips                  = getIps($net);
	$ifaces{$net}{'int'}     = $np->cfg->getInterface($net); 
	$ifaces{$net}{'qvlan'}   = $np->cfg->quarantineVlan($net);
	$ifaces{$net}{'nqvlan'}  = $np->cfg->nonquarantineVlan($net);
	$ifaces{$net}{'vip'}	 = ($np->cfg->virtualIP($net)) ? $np->cfg->virtualIP($net) : $ips[0]; 
	$ifaces{$net}{'d1'}	 = $ips[1]; 
	$ifaces{$net}{'d2'}	 = $ips[2]; 
	$ifaces{$net}{'r1'}	 = $ips[3]; 
	$ifaces{$net}{'r2'}	 = $ips[4]; 
	$ifaces{$net}{'mask'}	 = $ips[5]; 
	$ifaces{$net}{'bcast'}	 = $ips[6];

	if (exists $opts{'d'} && defined($opts{'d'})) {
		$ifaces{$net}{'redir'}   = ($opts{'d'} == 1) ? $np->cfg->primary_redirector($net) :
						       	       $np->cfg->secondary_redirector($net);
		$ifaces{$net}{'redir'}	 = 'unknown redirector' if !defined($ifaces{$net}{'redir'});
	}
}

print "#!/bin/bash\n";
print "#\n#  LVS Config for ".$names->{$rord}.' '.$opts{$rord}."\n#\n";

print "
# set up tagged interfaces
$MODPROBE 8021q
$IFCONFIG eth1 up

";

foreach (keys %ifaces) {

	next if (!defined($ifaces{$_}{'qvlan'}) || !defined($ifaces{$_}{'nqvlan'})); 

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

sub realserver ($) {
	my $ifaces = shift;

	print "# Setup Realserver Loopback interfaces and routes\n\n";

	foreach (keys %$ifaces) {
		printf("# %s network\n", $_);
		my($s, $n) = (split(/\./, $ifaces->{$_}{'vip'}))[2,3];

		printf("%s lo:%s.%s %s broadcast %s netmask 0xffffffff up\n",
							   $IFCONFIG,
							   $s, $n,
							   $ifaces->{$_}{'vip'},
							   $ifaces->{$_}{'bcast'});
		
		printf("%s add -host %s dev lo:%s.%s\n\n", $ROUTE,
							   $ifaces->{$_}{'vip'},
							   $s, $n);
	}
	print <<END
# hiding interface lo, will not arp
echo "1" >/proc/sys/net/ipv4/conf/all/hidden
cat       /proc/sys/net/ipv4/conf/all/hidden
echo "1" >/proc/sys/net/ipv4/conf/lo/hidden
cat       /proc/sys/net/ipv4/conf/lo/hidden
END

}

sub director ($) {

	my $ifaces     = shift;
	my $cur_redir  = "";

	printf("echo \"#     node                func::ip/netmask/interface/broadcast\" > %s\n", $HARESOURCES);

	foreach (keys %$ifaces) {
		my $n = ($ifaces{$_}{'qvlan'}) ? '.'.$ifaces{$_}{'qvlan'} : "";
		if ($cur_redir ne $ifaces->{$_}{'redir'}) {
			$cur_redir = $ifaces->{$_}{'redir'};
			printf("echo \"%-50s    \\\\\" >> %s\n", $cur_redir, $HARESOURCES);
		}
		printf("echo \"\t\t\t\tIPaddr2::%s/32/%s%s/%s \\\\\" \t>> %s\n",
								    $ifaces->{$_}{'vip'}, 
								    $ifaces->{$_}{'int'},
								    $n,
								    $ifaces->{$_}{'bcast'},
								    $HARESOURCES);
	}

	printf("echo \"\t\t\t\tldirectord\" >> %s\n\n", $HARESOURCES);

	print <<END2
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

#echo 1048576 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max # 512 MB
#echo 2097152 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max # 1024 MB
#echo 4194304 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max # 2048 MB

END2
	;
	my $memsize = getmem();
	print "# getmem says we have at least $memsize MB in the local machine\n";
	if ($memsize == 2048) {
		print "echo 4194304 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max # 2048 MB\n";
	} 
	elsif ($memsize == 1024) {
		print "echo 2097152 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max # 1024 MB\n";
	} 
	else {
		print "echo 1048576 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max # 512 MB\n";
	}

	print <<END
# start heartbeat
/etc/init.d/heartbeat stop
/etc/init.d/heartbeat start

END
}

sub ip2int ($) {
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

sub int2ip ($) {
	my $i = shift;
	my @o;

	$o[0] = ($i & 0xff000000) >> 24;
	$o[1] = ($i & 0x00ff0000) >> 16;
	$o[2] = ($i & 0x0000ff00) >> 8;
	$o[3] =  $i & 0x000000ff;

	return(join('.', @o));
}

sub getIps ($) {

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

sub getmem() {
	open(FD, "/proc/meminfo") || return 512;
	my $ms = 0;
	while(my $l = <FD>) {
		if ($l =~ /^MemTotal:\s*(\d+)/) {
			$ms = $1;
			last;
		}
	}
	close(FD);
	$ms /= 1024;
	return 2048 if ($ms > 2048);
	return 1024 if ($ms > 1024);
	return 512;
}

