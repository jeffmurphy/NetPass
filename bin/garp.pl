#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/garp.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

garp.pl - produce gratuitous ARPs

=head1 SYNOPSIS

 garp.pl <-i interface> [-m macaddress] [-a ipaddress] [-n #] [-h] [-v]
     -i interface         send G-ARPs out using this interface
     -M macaddress        use this mac as the ether-source (default = interface mac)
     -m macaddress        use this mac as the sender-mac (default = interface mac)
     -a ipaddress         use this ipaddress as the sender-ip (default = interface's ipaddress)
     -R routeripaddr      ip address to arp for (-a and -R are mutually exclusive)
     -n #                 send this number of G-ARPs
     -r secs              repeat every "secs" seconds (default is to only send them once)
     -v                   verbose
     -h                   this message

=head1 OPTIONS

=over 8

=item B<-i interface>

When sending out the gratuitous ARP, transmit it from this interface. If no other
parameters are given (particularly the B<-m> or B<-a> parameters) then the ARP packet
will contain the IP address and MAC address of this interface. If the interface has no
IP address, then we'll fill in something bogus (basically we'll change the first octet
of the IP address we're looking for to a "10".

=item B<-D>

Enable debugging. This option causes this script to run in the foreground. Otherwise
this script will detach and run in the background.

=back

=head1 DESCRIPTION

This application does two things: a) sends out gratuitous ARPs on interfaces that have IPs 
configured and b) sends out ARP requests for the local router on interfaces that have
no IP address configured. 

When we move NetPass clients from one VLAN to another (quarantine to non-quarantine) 
the clients will hang until the cached router ARP/IP combination times out of their local
machine. For the quarantined network, we are the local router, so we can use gratuitous
ARPs to force clients to update their cache. On the non-quarantine networks, we are not
the local router so we can either forge a gratuitous ARP (complicated) or broadcast an
ARP request and get the local router to reply (simpler). We do the latter.

=over 8

=item Gratuitous Arp on Quarantine Network

If we're given an IP address and a MAC address, or can discover both of those by
examining the specified interface (which is a required parameter), then we'll construct a 
gratuitous ARP packet and transmit it out the specified interace.

=item ARP Request on Non-Quarantine Network

If we're only given an interface, and determine that the interface has no associated
IP address, then we'll construct an ARP request and send it out. The request will
get the local router to reply, causing clients on the segment to update their caches. 
This is the simpler method because it doesn't require that we determine the local router's
MAC address. Forging a gratuitous ARP would require that.

To create the ARP request, we look in C<netpass.conf> and determine the good/bad VLAN
IDs for the interface. Given those, we can determine the IP address of the "bad" VLAN.
This will be the IP address of the local router in the "good" VLAN. We can then create
an ARP request with that IP, an empty MAC field, a bogus requester IP address and the
real MAC address for our "good" interface. This packet will cause the local router to
reply and clients will update their caches.

=back

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: garp.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

=cut

use strict;
use Socket;
use Getopt::Std;
use lib '/opt/netpass/lib';
use Pod::Usage;

use NetPass;
use NetPass::Config;
use NetPass::LOG qw(_log _cont);

NetPass::LOG::init [ 'garp', 'local0' ];

my %opts;


getopts('i:a:n:m:r:hvD', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};
pod2usage(1) if !exists $opts{'i'}; # interface is required

my $D = exists $opts{'D'} ? 1 : 0;

# if $ip is not defined, then this is an unconfigured
# interface, sitting on the 'good' (non-quarantined) VLAN
# we want to construct an ARP packet that will get the real
# router to reply with it's MAC so that all clients can recache

print "Determining hw and ip addr of $opts{'i'} ..\n" if $D;

my ($ma, $ip) = get_hwaddr($opts{'i'});

my ($rtr_ma, $pkt);

die "unable to determine hwaddr for interface $opts{'i'}" 
  if ( !defined($ma) );

my $np = new NetPass(-config => defined $opts{'c'} ? $opts{'c'} :
			     "/opt/netpass/etc/netpass.conf",
			     -debug => exists $opts{'D'} ? 1 : 0,
			     -quiet => exists $opts{'q'} ? 1 : 0);
	
die "failed to create NetPass object" unless defined $np;
	
if ( !defined($ip) ) {
    print $opts{'i'}." mac is ".join(':', @$ma)." but no IP defined.\n" 
      if $D;

    # since we have no IP we must be the non-quarantined interface
    # if we've been given an IP address to use (opt'a'), then we'll use
    # it. otherwise we'll derive the IP address by doing:

    if (exists $opts{'a'}) {
	$ip = splitIP($opts{'a'});
	if (exists $opts{'v'}) {
	    print "no IP address on $opts{'i'} but -a given. we'll go with that\n";
	    print "ip = $ip ", join('.', @$ip), "\n";
	}
    } else {
     
	# 1. determine quarantine vlan id for this interface (based on
	#    the non-quarantine vlan id, which we already know)
	
	print "Determine quar/nonquar VLAN ids for $opts{'i'}\n" if $D;

	my $interface = $opts{'i'};
	if ($interface !~ s/\.(\d+)$//) { # strip the existing vlan tag
	    die "$interface isnt of the form \"ethX.VLAN\" eg eth1.812\n";
	}
	
	my ($nonquar, $quar) = $np->{'cfg'}->availableVlans(-interface => $interface,
							    -vlan      => $1);
	
	die "cant determine quar/nonquar VLAN ids for $interface" 
	  unless defined($nonquar) && defined($quar);
	
	print "quar $quar nonquar $nonquar\n" if $D;
	
	# 2. determine the IP address of the quarantine vlan interface
	
	print "Determine IP addr for ${interface}.${quar}\n" if $D;
	
	my ($q_ma, $q_ip) = get_hwaddr($interface.".".$quar);
	
	# 3. use that IP address when ARPing, along with our mac address
	
	print "construct_arp..\n" if $D;

	$ip = $q_ip;
    }


	
    # what we do here is forge an ARP packet with our MAC address
    # but with the router's IP address. the router (a cisco at this time)
    # reports a duplicate address violation and sends out a gratuitous
    # ARP. not exactly pretty, but it works.
    
    $pkt = construct_arp($ip,             # our IP address
			 $ma,             # our MAC address
			 $ip,             # who we're looking for
			 [0,0,0,0,0,0]);
} else {
    print "$opts{'i'} has an IP addr defined.. doing gratuitous arp..\n" if $D;
    my $o_a = exists $opts{'a'} ? splitIP($opts{'a'}) : $ip;
    my $o_m = exists $opts{'m'} ? splitMAC($opts{'m'}) : $ma;

    if ($D) {
	print "Using IP : ", join('.', @$o_a), "\n";
	print "Using MA : ", join(':', @$o_m), "\n";
    }

    $pkt = construct_gratuitous_arp($o_a, $o_m);
}

my $n = (exists $opts{'n'} && $opts{'n'} > 0) ? $opts{'n'} : 4;

#define PF_PACKET 17
#define SOCK_PACKET 10

socket(OUT, 17, 10, 0x300) || die "socket: $!";
my $from = pack('SZ16', 0, $opts{'i'});

if (exists $opts{'r'}) {
    print "send $n packets every $opts{'r'} seconds..\n" if $D;
} else {
    print "non-repeat mode. sending $n packets once.\n" if $D;
}

my $daemon = 0;
my $pidDir = $np->policy('PID_DIR') || "/var/run/netpass";
my $pidFn  = $pidDir."/garp.PID.pid";
if (! exists $opts{'D'}) {
    daemonize("garp", $pidDir, $pidFn, $opts{'i'});
    $daemon = 1;
}


my $once = 1;
while ($once || exists $opts{'r'}) {
    $once = 0;
    for (my $count = 0 ; $count < $n ; $count++) {
	print "sending ARP #$count\n" if $D;
	#	$rtr_ma = discover_router_ma($opts{'i'}, $ma, [ 128,205,12,94 ]);
	
	my $slen = send(OUT, $pkt, 0, $from);
	die "send failed ($from): $!" unless defined $slen;
    }
    sleep($opts{'r'})
      if exists $opts{'r'} && ($opts{'r'} > 0);
}

close(OUT);

exit 0;

###############################


=head1 API

=head2 $ma = discover_router_ma(interface_name, mymac, remoteipaddr)

This routine will send out an ARP using mymac as the source, requesting
resolution of remoteipaddr to a mac address.

=cut

sub discover_router_ma {
    my $in  = shift;
    my $mma = shift;
    my $ip  = shift;

    my $null_mac = [ 0,0,0,0,0,0 ];
    my $null_ip  = [ 0,0,0,0 ];

    print "discover_router_ma: socket\n" if $D;

    socket(DMA, 17, 10, 0x300) || die "socket: $!";
    my $from = pack('SZ16', 0, $in);
    my $pkt  = construct_arp([128,205,12,94], $mma, $ip, $null_mac);
    print "discover_router_ma: send\n" if $D;
    my $slen = send(DMA, $pkt, 0, $from);
    die "send failed ($from): $!" unless defined $slen;

    close(DMA);
    print "discover_router_ma: done\n" if $D;
}

=head2 ($ma, $ia) = get_hwaddr(interface_name)

This routine uses socket and ioctl to fetch the hardware address and
IP address of the named interface. e.g. C<get_hwaddr("eth0")> It returns
two ARRAY references on success, C<(undef, undef)> on failure.

=cut


sub get_hwaddr {
    my $i = shift;
    socket(SH, AF_INET, SOCK_DGRAM, 0) || die "socket: $!";

    die "interface name too long (IF_NAMESIZE = 16)" 
      if length($i) > 16;

    print "get_hwaddr: MA ioctl\n" if $D;

    my $ifr = pack('a16', $i);
#define SIOCGIFHWADDR     0x8927
#define SIOCGIFADDR       0x8915
    my $rv  = ioctl SH, 0x8927, $ifr;
    return (undef, undef) if ( !defined($rv) || ($rv ne "0 but true") );
    my ($junk, $family);
    my @ma;
    ($junk, $family, @ma) = unpack('A16SC6', $ifr);
    
    if (exists $opts{'D'}) {
	print "$i MAC addr   : ";
	
	for (my $j = 0; $j < 6 ; $j++) {
	    printf "%.2X", $ma[$j] & 0xff;
	    print ":" if $j < 5;
	}
	print "\n";
    }

    print "get_hwaddr: IP ioctl\n" if $D;

    $ifr = pack('a16', $i);
    $rv  = ioctl SH, 0x8915, $ifr;
    return (\@ma, undef) if ( !defined($rv) || ($rv ne "0 but true") );
    my @ia;
    ($junk, $family, @ia) = unpack('A18SC4', $ifr);

    if (exists $opts{'D'}) {
	DumpRec_Hex($ifr, 32);
	
	print "$i IP  addr   : ";
	
	for (my $j = 0; $j < 4 ; $j++) {
	    printf "%.2X", $ia[$j] & 0xff;
	    print "." if $j < 3;
	}
	print "\n";
    }

    close(SH);

    return (\@ma, \@ia);
}

=head2 $pkt = construct_arp(eth-dmac, eth-smac, sender-ipaddr, sender-macaddr, target-ipaddr, target-macaddr)

Construct an ARP packet. Returns a scalar on success. C<undef> on error.

=over 8

=item eth-dmac

The destination MAC to put in the ethernet header. Defaults to broadcast if 
undef.

=item eth-smac

The source MAC to put in the ethernet header. Required, must be defined.

=item sender-ipaddr

The IP address of the machine sending the ARP packet. 

=item sender-macaddr

The MAC address of the machine sending the ARP packet. Defaults to eth-smac
if undef.

=item target-ipaddr

The IP address of the host we want to learn the MAC of.

=item target-macaddr

The MAC address of the host we want to know about. Typically left as all zeros and 
filled in as part of the ARP reply packet.

=back

=cut

sub construct_arp {
    my ($sip, $sma, $tip, $tma) = (shift, shift, shift, shift);

    my $packet = pack('C6', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff); # ether_dhost
    $packet   .= pack('C6', @$sma);    # ether_shost
    $packet   .= pack('n', 0x0806);    # ether_type = ETHERTYPE_ARP
    $packet   .= pack('n', 1);         # ar_hdr = ARPHRD_ETHER
    $packet   .= pack('n', 0x0800);    # ar_pro = ETHERTYPE_IP
    $packet   .= pack('C', 6);         # ar_hln = 6 (hw len)
    $packet   .= pack('C', 4);         # ar_pln = 4 (proto len - the ipv4 addr)
    $packet   .= pack('n', 1);         # ARPOP_REQUEST
    $packet   .= pack('C6', @$sma);    # __ar_sha
    $packet   .= pack('C4', @$sip);    # __ar_sip
    $packet   .= pack('C6', @$tma);    # __ar_tha
    $packet   .= pack('C4', @$tip);    # __ar_tip

    return $packet;
}

=head2 $pkt = construct_gratuitous_arp(ipaddr, macaddr)

Construct the ARP packet. Use the given IP address
and MAC address to populate the packet. the MAC address will also be
used to populate the C<ether_shost>. The C<ether_dhost> will be the
broadcast (FF:FF:FF:FF:FF:FF). Returns a scalar on success. C<undef> on error.

=cut

sub construct_gratuitous_arp {
    my ($ip, $ma) = (shift, shift);

    my $packet = pack('C6', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff); # ether_dhost
    $packet   .= pack('C6', @$ma);     # ether_shost
    $packet   .= pack('n', 0x0806);    # ether_type = ETHERTYPE_ARP
    $packet   .= pack('n', 1);         # ar_hdr = ARPHRD_ETHER
    $packet   .= pack('n', 0x0800);    # ar_pro = ETHERTYPE_IP
    $packet   .= pack('C', 6);         # ar_hln = 6 (hw len)
    $packet   .= pack('C', 4);         # ar_pln = 4 (proto len - the ipv4 addr)
    $packet   .= pack('n', 1);         # ARPOP_REQUEST
    $packet   .= pack('C6', @$ma);     # __ar_sha
    $packet   .= pack('C4', @$ip);     # __ar_sip
    $packet   .= pack('C6', 0,0,0,0,0,0);
    $packet   .= pack('C4', @$ip);     # __ar_tip

    return $packet;
}

sub splitIP {
    my $i = shift;
    die "malformed IP address \"$i\"" 
      if ($i !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
    return [ split(/\./, $i) ];
}

sub splitMAC {
    my $m = shift;
    $m =~ tr [A-Z] [a-z];
    die "malformed MAC address" 
      unless ($m =~ /^[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$/);

    my @m2;
    foreach my $x (split(/:/, $m)) {
	push @m2, hex($x);
    }
    
    return \@m2;
}


sub DumpRec_Hex {
    my $r = shift;
    my $l = shift;

    my $MAXBYTE = 20;
    my($yet, $addr, $dl);

    $yet  = 1;
    $addr = 0;

    while($yet) {
        $dl  = (($l-$addr)>$MAXBYTE) ? $MAXBYTE : ($l-$addr);
        $yet = (($l - $addr) >= $MAXBYTE);
        printf("\n%.8x : ", $addr);
        DRH_DumpIt($r, $addr, $dl, $MAXBYTE);
        $addr += $MAXBYTE;
    }
    print "\n";
}

sub DRH_DumpIt {
    my $c = shift;
    my $s = shift;
    my $l = shift;
    my $MAXBYTE = shift;
    my $byte;

    my $i;

    if(defined($MAXBYTE)) {
        for($i=0 ; $i < $l; $i++) {
            $byte = unpack("C", substr($c, $s+$i, 1));
            printf("%.2x", $byte);
            if( ($i+1)%4 == 0 ) {
                printf(" ");
            }
        }
        if($l < $MAXBYTE) {
            for(;$i<$MAXBYTE;$i++) {
                printf("..");
                if( ($i+1)%4 == 0 ) {
                    printf(" ");
                }
            }
        }

        for($i=0; $i<$l; $i++) {
            $byte = unpack("C", substr($c, $s+$i, 1));
            if( ($byte >= 32) && ($byte <= 122) ) {
                printf("%c",$byte);
            } else {
                printf(".");
            }
        }

    }
}



sub cleanPidFile {
    my $pf = $pidFn;
    $pf =~ s/PID/$$/;

    _log "INFO", "deleting pidFile $pf\n";
    unlink($pf) || 
      _log ("WARN", "couldnt unlink pid file $pf : $!");
}

sub sigHandler {
    my ($sig) = @_;
    _log ("ERROR", "pid $$ caught SIG$sig -- clean pid file and exit\n");
    cleanPidFile();
    exit 0;
}

# borrowed from mailgraph.pl

sub daemonize
{
    use POSIX 'setsid';

    my ($myname, $pidDir, $pidFn, $if) = (shift, shift, shift, shift);

    chdir $pidDir or die "$myname: can't chdir to $pidDir: $!";
    -w $pidDir or die "$myname: can't write to $pidDir\n";

    open STDIN, '/dev/null' or die "$myname: can't read /dev/null: $!";
    open STDOUT, '>/dev/null'
      or die "$myname: can't write to /dev/null: $!";

    defined(my $pid = fork) or die "$myname: can't fork: $!";
    if($pid) {
	# parent
	$pidFn =~ s/PID/$pid/;
	open PIDFILE, "> " . $pidFn
	  or die "$myname: can't write to $pidFn: $!\n";
	print PIDFILE "$pid\n$if\n";
	close(PIDFILE);
	exit 0;
    }
    # child

    _log ("INFO", "daemonized.");

    setsid                  or die "$myname: can't start a new session: $!";
    open STDERR, '>&STDOUT' or die "$myname: can't dup stdout: $!";

    $SIG{'INT'} = \&sigHandler;
    $SIG{'HUP'} = \&sigHandler;
    $SIG{'QUIT'} = \&sigHandler;
    $SIG{'ABRT'} = \&sigHandler;
    $SIG{'TERM'} = \&sigHandler;
}


END {
    cleanPidFile() if $daemon;
}

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 CREDITS

Based on "garp" (C code) by Alexandre Cassen <acassen@linux-vs.org>

=cut

