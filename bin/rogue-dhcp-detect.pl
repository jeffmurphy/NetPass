#!/opt/perl/bin/perl -w

use strict;
use Getopt::Std;
use Pod::Usage;

use lib qw(../lib);
use NetPass::LOG qw(_log _cont);
use NetPass;
use NetPass::Config;

use FileHandle;
use IO::Select;

#NetPass::LOG::init [ 'reset', 'local0' ]; #*STDOUT;

#$SIG{CHLD} = "IGNORE";

my %opts;

getopts('U:Dqhc:', \%opts);
pod2usage(2) if exists $opts{'h'}  || exists $opts{'?'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(	-cstr 	=> exists $opts{'c'} ? $opts{'c'} : undef,
                     	-dbuser => $dbuser,
			-dbpass => $dbpass,
                     	-debug  => exists $opts{'D'} ? 1 : 0,
                     	-quiet  => exists $opts{'q'} ? 1 : 0,
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

#exit;
		
###################### CONFIG VARS ####################################

my $debug	= 1;
my $quiet	= 0;

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
my $ouiFile = "../etc/oui.txt";

my $fhIfMap = {};

########################################################################

# convert to seconds
$reportFrequency = $reportFrequency * 60;

# unbuffer output
$|=1;

# create a filehandle group
my $fhGroup 	= IO::Select->new();

# when true, we exit
my $programExit	= 0;

# a hash, indexed by the ethernet address, of any rogues found.
# $roguesFound->{ethernet address} = ip address
my $roguesFound = {};

# the last time a report was sent out
my $lastReport  = time;

# use oui file for determining what manufacturer made this device
my $ouiCache    = loadOUI($ouiFile);

# for each VLAN, open a tcpdump filehandle and push it into the filehandle group
foreach my $interface (@interfaces) {
	next if(!ifConfigured($interface));

	# the -S in the tcpdump command is very important... without -S, tcpdump keeps track of
	# all the connections it has seen so it can generate relative sequence numbers rather
	# than absolute sequence numbers. over time, this will increase the address space used
	# by tcpdump, simulating a memory leak.

	my $fh = new FileHandle "/usr/sbin/tcpdump -Slne -i$interface udp src port 67 2>&1 |";
	if(defined($fh)) {
		print "Listening to traffic on IF $interface\n" if(!$quiet);
		$fhGroup->add($fh);
		$fhIfMap->{$fh} = $interface;
	}
}

while(!$programExit) {

	# check to see if any of the filehandles have input
	if (my @fhs = $fhGroup->can_read(0)) {

		# @fhs is an array of the filehandle that have input waiting to be read

		# foreach filehandle that has input to be read, get the input and parse it
		foreach my $fh (@fhs) {
			
			my $line = $fh->getline;
			my ($srcEth, $dstEth, $srcIp, $dstIp) = ('','','','');

			($srcEth, $dstEth, $srcIp, $dstIp) = $line =~ /(\w+\:\w+\:\w+\:\w+\:\w+\:\w+) (\w+\:\w+\:\w+\:\w+\:\w+\:\w+)*.+ (\d+\.\d+\.\d+\.\d+)\.bootps > (\d+\.\d+\.\d+\.\d+).+/; 

			if(!$srcIp) {	
				# this filter catches bad matches
				print "NOMATCH:\t$line" if($debug);

			} elsif($srcIp =~ /\.25\d$/) {
				# this filter catches dhcrelays
				print "DHCRELAY:\t$srcIp - $srcEth\n" if($debug);

			} elsif( $allowed->{$srcIp} ) {
				# this filter catches our exceptions
				print "EXCEPTION:\t$srcIp - $srcEth\n" if($debug);

			} else {
				# anything else, should be a rogue server
				$roguesFound->{$srcEth}->{'ip'}	  = $srcIp;
				$roguesFound->{$srcEth}->{'vlan'} = $fhIfMap->{$fh};
				$roguesFound->{$srcEth}->{'count'}++;
				print "ROGUE:\t$srcIp - $srcEth - " . $fhIfMap->{$fh} . " - " . $roguesFound->{$srcEth}->{'count'} . "\n" if(!$quiet);
			}
		}

	} else {
		print "no line\n" if($debug);
	}

	# if it's time to report, report
	if((time - $lastReport) >= $reportFrequency) {
		sendReport();
		$lastReport = time;
		$roguesFound = {};
	}	

	# let's sleep for a while and wait for some input to queue up
	sleep($checkFrequency);

#	$programExit = 1;

}

# if we're exiting, close all the filehandles
print "Stop Listening...\n" if(!$quiet);
foreach my $fh ( @{$fhGroup->handles} ) {
	$fh->close;
}

exit;


########################################################################

sub ifConfigured {
	my ($interface) = @_;
	
	return 0 if(!defined($interface));

	# check that the interface exists on this machine
	if(system("/sbin/ifconfig -s $interface > /dev/null 2>&1") == 0) {
		return 1;
	}
	print "Interface $interface is not configured on this device\n" if(!$quiet);
	return 0;

} # end sub

sub sendReport {

	my $msg  = '';

	foreach my $eth ( keys %$roguesFound ) {
		my $ip    = $roguesFound->{$eth}->{'ip'};
		my $vlan  = $roguesFound->{$eth}->{'vlan'};
		my $count = $roguesFound->{$eth}->{'count'};

		$eth = sprintf('%02s:%02s:%02s:%02s:%02s:%02s', split(':', $eth));
	   	
		$msg .= "ip: $ip - eth: $eth - vlan: $vlan - requests: $count";

		my $lookup = sprintf('%02s:%02s:%02s', split(':', $eth));

		$msg .= " - manufacturer: " . $ouiCache->{$lookup} if($ouiCache->{$lookup});
		$msg .= "\n";
	}

	if($msg ne '') {
		$msg  = "ROGUE DHCP SERVERS DETECTED:\n\n" . $msg;
		print "$msg\n";
	}

	return 1;

} # end sub

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

