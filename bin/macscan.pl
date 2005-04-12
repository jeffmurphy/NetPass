#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/macscan.pl,v 1.5 2005/04/12 20:53:43 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

DO NOT USE. NOT FINISHED YET. NOT TESTED.

macscan.pl - periodically scan the switches looking for unknown MACs as well
as ports with multiple MACs.

=head1 SYNOPSIS

 macscan.pl [-q] [-D] [-c cstr] [-U dbuser/dbpass] [-t thread-queue-size]
     -q             be quiet. exit status only.
     -D             enable debugging
     -c             db connect string
     -U             db user[/pass]
     -t             thread queue size

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

=item B<-t thead-queue-size> 

A number denoting how many switches to delegate to each thread for monitoring.
The default is 20. If you have 100 switches in your NetPass configuration,
5 threads will be spawned. Each thread will linearly search each switch for
multi-mac violations. Each thread requires a connection to the database, 
so don't set this number too low or you'll needless use DB resources.

=back

=head1 DESCRIPTION

This script fetches all configured switches (see L<netpass.conf>) and will continuously
scan each switch for the MAC addresses attached to its ports. If an unregistered
MAC is found, the port is placed back into the quarantine. 

If multiple MACs are found, and one (or more) is unregistered, the port is placed
back into the quarantine and the registered MACs are pointed at a web page 
letting them know why they've been quarantined. The unregistered MACs are implicitly
directed to the default webpage.

This script will only quarantine ports if the MULTI_MAC configuration setting
is set to ALL_OK.

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

$Id: macscan.pl,v 1.5 2005/04/12 20:53:43 jeffmurphy Exp $

=cut


use strict;
use threads;
use Getopt::Std;
use lib '/opt/netpass/lib/';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;

BEGIN {
    use Config;
    $Config{useithreads} or die "Recompile Perl with threads to run this program.";
}

NetPass::LOG::init [ 'macscan', 'local0' ];

#pod2usage(1) if $#ARGV != 0;

my %opts : shared;
getopts('c:U:qt:Dh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

# foreach network in <switchmap> {
#    foreach switch in network {
#       ($a, $b) = get_mac_port_table()
#    }
#    if UNKNOWN MAC {
#       moveport switch/port -> bad
#       if MULTIPLE MACS {
#          set_message(MULTIPLE_OK_WITH_UNKNOWN)
#       }
#    }
#

my $D : shared = exists $opts{'D'} ? 1 : 0;

my $dbuser : shared;
my $dbpass : shared;
($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $cstr : shared = exists $opts{'c'} ? $opts{'c'} : undef;

print "Connecting to NetPass ..\n" if $D;

my $np = new NetPass(-cstr   => $cstr,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "Failed to connect to NetPass: $np\n" unless (ref($np) eq "NetPass");

print "Finding all networks ..\n" if $D;

my $nws = $np->cfg->getNetworks();
my @threads;

my $allSwitches = $np->cfg->getSwitches();


# we devide the switches up into groups of "$ps"
# and give each group out to a thread for periodic
# polling

my $ps = exists $opts{'t'} ? $opts{'t'} : 20;

for(my $i = 0 ; $i <= $#{$allSwitches} ; $i += $ps) {
	my $end = $i + $ps - 1;
	$end = $#{$allSwitches} unless ($#{$allSwitches} > $end);

	print "Spawning thread for switches $i thru $end\n" if $D;
	push @threads, new threads (\&thread_entry, @{$allSwitches}[$i..$end]);
	_log("DEBUG", "thread ".$threads[$#threads]->tid." created\n");
}

print "Parent thread waiting\n" if $D;
$threads[0]->join;
print "Parent thread joined\n" if $D;


exit 0;

sub thread_entry {
        my @switches = @_;

	my $tid = threads->tid();

	print "[$tid] Creating thread-local NetPass Connection\n" if $D;

	# perl threads require that each thread have a private DBH. 
	# this means we need a private NP.
	
	my $np = new NetPass(-cstr   => $cstr,
			     -dbuser => $dbuser, -dbpass => $dbpass,
			     -debug  => exists $opts{'D'} ? 1 : 0,
			     -quiet  => exists $opts{'q'} ? 1 : 0);
	
	die "Failed to connect to NetPass: $np\n" unless (ref($np) eq "NetPass");

	# fetch list of ports we "know" about from the config. we
	# use this list to quickly throw away data we aren't interested in

	my %ports;

	# pre-create the SNMP objects for speed. pre-fetch valid
	# ports, again, for speed.

	print "[$tid] Pre-creating SNMP objects.\n" if $D;

	my %snmp;
	foreach my $switch (@switches) {
		foreach my $p (@{$np->cfg->configuredPorts($switch)}) {
			$ports{$p} = 1;
		}
		my ($r, $w) = $np->cfg->getCommunities($switch);
		$snmp{$switch} = new SNMP::Device('hostname'       => $switch,
						  'snmp_community' => $w
						 );
	}

	print "[$tid] Entering loop.\n" if $D;

	while ( 1 ) {
		for my $switch (sort keys %snmp) {
			print "[$tid] Wokeup. Processing $switch ..\n" if $D;
			_log("DEBUG", "thread ".threads->self->tid. " wokeup\n");
			
			my ($mp, $pm) = $snmp{$switch}->get_mac_port_table();
			
			# foreach port, if port contains unknown mac -> quarantine
			

			foreach my $p (keys %$pm) {
				if (!exists $ports{$p}) {
					#print "skipping port $p\n";
				} else {
					
					# check each mac on this port. if any are unknown -> quar
					
					my $portIsOK = 1; # assume true
					my @okMacs;
					my @nOkMacs;
					my $mac;
					
					foreach $mac (@{$pm->{$p}}) {
						my $mok = $np->db->macIsRegistered($mac);

						if ( $mok == -1 ) {
							_log("ERROR", "macIsRegistered($mac) failed: ".$np->db->error()."\n");
						}
						elsif( $mok == 0 ) {
							$portIsOK = 0;
							push @nOkMacs, $mac;
						} 
						else {
							push @okMacs, $mac;
						}
					}
					
					# if any of the MACs were bad, then portIsOK = 0
					# and we need to:
					#     a) set a message on the OK macs so they
					#        understand why they've been quarantined
					#     b) quarantine port
					
					if( ! $portIsOK ) {
						if ($#{$pm->{$p}} > 0) {
							foreach $mac (sort @okMacs) {
								print "[$tid] Found an OK mac with nok neighbors. Adding mmac result..\n" if $D;
								_log("INFO", "Found OK mac $mac on multimac port $switch/$p\n");
								$np->db->addResult(-mac => $mac,
										   -type => 'manual',
										   -id => 'msg:multi_mac');
							}
						}
						
						print "[$tid] Found nok macs ".(join(',', sort @nOkMacs))." on $switch/$p\n" if $D;
						_log("INFO", "Found unreg'd macs ".(join(',', sort @nOkMacs))." on $switch/$p\n");

						$np->movePort(-switch => $switch,
							      -port   => $p,
							      -vlan   => 'quarantine');
					}
				}
			}
		}
		sleep (10);
	}
}
