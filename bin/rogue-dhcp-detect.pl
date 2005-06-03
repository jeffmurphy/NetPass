#!/opt/perl/bin/perl -w
#
#   $Header: /tmp/netpass/NetPass/bin/rogue-dhcp-detect.pl,v 1.4 2005/06/03 20:53:33 rcolantuoni Exp $
#
#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

rogue-dhcp-detect.pl - sniffs NetPass interfaces for traffic from rogue dhcp servers.

=head1 SYNOPSIS

 rogue-dhcp-detect.pl [-q] [-D] [-c cstr] [-U dbuser/dbpass]
     -q             be quiet. exit status only.
     -D             enable debugging
     -c             db connect string
     -U             db user[/pass]

=head1 OPTIONS

=over 8

=item B<-q>

Be quiet, don't print anything. Just exit with non-zero status if
an error occurred. Otherwise, exit with zero status.

=item B<-D>

Enable debugging output.

=item B<-c cstr>

Connect to alternate database.

=item B<-U user/pass>

Credentials to connect to the database with.

=back

=head1 DESCRIPTION

This script fetches all configured interfaces (see L<netpass.conf>) and will continuously
scan each interface for dhcp server traffic from unknown devices.
If an invalid device is sending dhcp server traffic, the port is disabled.

=head1 AUTHOR

Rob Colantuoni <rgc@buffalo.edu>

=cut

use strict;
use threads;
use Getopt::Std;
use Pod::Usage;
use Net::Pcap;
use NetPacket::Ethernet;

use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass;

use FileHandle;

BEGIN {
    use Config;
    $Config{useithreads} or die "Recompile Perl with threads to run this program.";
}

###################### CONFIG VARS ####################################

my $allowed 	= {
			'128.205.1.32'    => 'ccdhcp-resnet3',
			'128.205.1.33'    => 'ccdhcp-resnet4',
			'128.205.1.26'	  => 'npw1',
			'128.205.1.27'	  => 'npw2',
			'128.205.159.122' => 'dhcp relay exception',
			'128.205.159.123' => 'dhcp relay exception',
			'128.205.159.126' => 'dhcp relay exception',
		  };

# file containing a map of the first half of a mac address to manufacturer
my $ouiFile = "/opt/netpass/etc/oui.txt";

########################################################################

my %opts;

getopts('U:Dqhc:', \%opts);
pod2usage(2) if exists $opts{'h'}  || exists $opts{'?'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $debug	= exists $opts{'D'} ? 1 : 0;
my $quiet	= exists $opts{'q'} ? 1 : 0;

NetPass::LOG::init *STDOUT if $debug;
NetPass::LOG::init [ 'rogue-dhcp-sniff', 'local0' ] unless $debug;

my $np = new NetPass(	-cstr 	=> exists $opts{'c'} ? $opts{'c'} : undef,
                     	-dbuser => $dbuser,
			-dbpass => $dbpass,
                     	-debug  => $debug,
                     	-quiet  => $quiet,
		    );

die "failed to create NetPass object" unless defined $np;

my @interfaces = ();

foreach my $network ( @{$np->cfg->getNetworks()} ) {
	my $interface = $np->cfg->interface($network);
	if( defined($np->cfg->nonquarantineVlan($network)) ) {
		push(@interfaces, "$interface.".$np->cfg->nonquarantineVlan($network));
	}
	if( defined($np->cfg->quarantineVlan($network)) ) {
		push(@interfaces, "$interface.".$np->cfg->quarantineVlan($network));
	}
}

die "no interfaces to listen on" if($#interfaces<0);

$np->DESTROY();

# unbuffer output
$|=1;

# use oui file for determining what manufacturer made this device
my $ouiCache    = loadOUI($ouiFile);

# when true, we exit
my $programExit	= 0;

# a hash, indexed by the ethernet address, of any rogues found.
# $roguesFound->{ethernet address} = ip address
my $roguesFound = {};

my @threads = ();

# for each interface, spawn a thread and push it into the threads array
foreach my $interface (@interfaces) {
	my $sniffer = pcapDescriptor($interface);
	push @threads, new threads (\&threadEntry, $sniffer, $interface);
	#my $t = new threads (\&threadEntry, $sniffer, $interface);
}

# wait for all threads to finish
$_->join foreach @threads;

$threads[0]->join;

exit 0;

########################################################################

sub threadEntry {
	my ($sniffer, $interface) = @_;

	my $tid = threads->tid();
	#print "$tid";  # causes segfault?? wtf!

	if(ref($sniffer)) {
		_log("DEBUG", "Thread [$tid] - Listening on interface $interface\n");
		Net::Pcap::loop($sniffer, -1, \&processPacket, 0);
		Net::Pcap::close($sniffer);
		_log("DEBUG", "Thread [$tid] - Done Listening on interface $interface\n");
	} else {
		_log("DEBUG", "Thread [$tid] - Not Listening on interface $interface\n");

		# without this sleep, the $tid throws a segfault?
		sleep(1);
	}
}

sub processPacket {
	my($user_data, $hdr, $pkt) = @_;
	print "got one!\n";

	my $eth_obj = NetPacket::Ethernet->decode($pkt);

	return if(!defined($eth_obj->{type}));
	return if( $eth_obj->{type} != 2048 );

	# 2048 (0x0800) - IP
	# 2054 (0x0806) - ARP 

        print("$eth_obj->{src_mac}:$eth_obj->{dest_mac} $eth_obj->{type}\n");	

	my $ip_obj = NetPacket::IP->decode($eth_obj->{data});
    
	if($ip_obj->{proto} == 11){
		# TCP = 6
		# UDP = 11
      		#my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
    	}

	return;
}


sub pcapDescriptor {
	my ($device) = @_;

	# promiscuous mode on
    	my $promisc = 1;
    	
	my $snaplen = 96;

    	my $timeout 	= 0;	# timeout  (ms)
    	my $optimize	= 1;    # optimize flag
    
	# dhcp
    	#my $filter = "udp src port 67";
    	my $filter = "";

	my ($err, $net, $mask, $filterCompiled);
 
    	if ( (Net::Pcap::lookupnet($device, \$net, \$mask, \$err) ) == -1 ) {
		_log("ERROR", "$err\n");
		return undef;
    	}
 
    	# open the descriptor
    	my $descriptor = Net::Pcap::open_live($device, $snaplen, $promisc, $timeout, \$err);
    	$descriptor || die "Can't create packet descriptor.  Error was $err";
 
    	if ( Net::Pcap::compile($descriptor, \$filterCompiled, $filter, $optimize, $net) == -1 ) {
        	die "Unable to compile filter string '$filter'\n";
    	}

    	# Make sure our sniffer only captures those bytes we want in
    	# our filter.
    	Net::Pcap::setfilter($descriptor, $filterCompiled);

    	# Return our pcap descriptor
	return $descriptor;
}

sub loadOUI {
	my ($filename) = @_;

	my $cache = {};

	my $fh = new FileHandle;	
	$fh->open($filename) || die "Couldn't open oui file: $filename!\n";

	while( my $line = <$fh>) {
		my($eth, $company) = split(/\|/, $line);
		$eth =~ s/\-/\:/g;
		$eth = lc($eth);
		$cache->{$eth} = $company;
	}

	$fh->close;

	return $cache;

} # end sub

