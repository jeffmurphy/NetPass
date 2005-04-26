#!/opt/perl/bin/perl -w
#
#   $Header: /tmp/netpass/NetPass/bin/rogue-dhcp-detect.pl,v 1.3 2005/04/26 20:35:36 rcolantuoni Exp $
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

use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass;
use NetPass::Config;

use FileHandle;

BEGIN {
    use Config;
    $Config{useithreads} or die "Recompile Perl with threads to run this program.";
}

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

my $checkFrequency  = 3;  # how often (in seconds) to check the tcpdump filehandles for input
my $reportFrequency = 20; # how often (in minutes) to send the report of rogues found

# file containing a map of the first half of a mac address to manufacturer
my $ouiFile = "/opt/netpass/etc/oui.txt";

my $fhIfMap = {};

########################################################################

# convert to seconds
$reportFrequency = $reportFrequency * 60;

# unbuffer output
$|=1;

# when true, we exit
my $programExit	= 0;

# a hash, indexed by the ethernet address, of any rogues found.
# $roguesFound->{ethernet address} = ip address
my $roguesFound = {};

# the last time a report was sent out
my $lastReport  = time;

# use oui file for determining what manufacturer made this device
my $ouiCache    = loadOUI($ouiFile);

my @threads = ();

# for each interface, spawn a thread and push it into the filehandle group
foreach my $interface (@interfaces) {
	my $sniffer = pcapDescriptor($interface);
	push @threads, new threads (\&threadEntry, $sniffer, $interface);
}

#print "Parent thread waiting\n" if $debug;
#$threads[0]->join;
#print "Parent thread joined\n" if $debug;

# wait for all threads to finish
$_->join foreach @threads;

exit 0;

########################################################################

sub threadEntry {
	my $sniffer   = shift;
	my $interface = shift;

	#my $tid = threads->tid();
	#print "$tid";  # causes segfault?? wtf!

	if(ref($sniffer)) {
		_log("DEBUG", "Thread [tid] - Listening on interface $interface\n");
#		Net::Pcap::loop($sniffer, -1, \&processPacket, 0);
		Net::Pcap::close($sniffer);
		_log("DEBUG", "Thread [tid] - Done Listening on interface $interface\n");
	} else {
		_log("DEBUG", "Not Listening on interface $interface\n");
	}
}

sub processPacket {
	my($user_data, $hdr, $pkt) = @_;
	print "got one!\n";
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
    	my $filter = "udp src port 67";

	my ($err, $net, $mask, $filterCompiled);
 
    	if ( (Net::Pcap::lookupnet($device, \$net, \$mask, \$err) ) == -1 ) {
		_log("DEBUG", "$err\n");
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

