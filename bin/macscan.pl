#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/macscan.pl,v 1.3 2005/04/12 14:18:12 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

DO NOT USE. NOT FINISHED YET. NOT TESTED.

macscan.pl - periodically scan the switches looking for unknown MACs as well
as ports with multiple MACs.

=head1 SYNOPSIS

 macscan.pl [-q] [-D] [-c cstr] [-U dbuser/dbpass]
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

=item B<-c config> 

Connect to alternate database.

=back

=head1 DESCRIPTION

This script looks thru <switchmap> (see L<netpass.conf>) and will continuously
scan each switch for the MAC addresses attached to its ports. If an unregistered
MAC is found, the port is placed back into the quarantine. 

If multiple MACs are found, and one (or more) is unregistered, the port is placed
back into the quarantine and the registered MACs are pointed at a web page 
letting them know why they've been quarantined. The unregistered MACs are implicitly
directed to the default webpage.

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

$Id: macscan.pl,v 1.3 2005/04/12 14:18:12 jeffmurphy Exp $

=cut


use strict;
use threads;
use Getopt::Std;
use lib '/opt/netpass/lib/';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;
require NetPass::Config;
require NetPass::SNMP;
require NetPass::DB;


BEGIN {
    use Config;
    $Config{useithreads} or die "Recompile Perl with threads to run this program.";
}

NetPass::LOG::init [ 'macscan', 'local0' ];

#pod2usage(1) if $#ARGV != 0;

my %opts;
getopts('c:U:qDh?', \%opts);
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

my $dbuser : shared;
my $dbpass : shared;
($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $cstr : shared = exists $opts{'c'} ? $opts{'c'} : undef;

my $np : shared = new NetPass(-cstr   => $cstr,
			      -dbuser => $dbuser, -dbpass => $dbpass,
			      -debug => exists $opts{'D'} ? 1 : 0,
			      -quiet => exists $opts{'q'} ? 1 : 0);

my $nws = $np->cfg->getNetworks();
my @threads;

foreach my $network (@$nws) {
    print "spawning thread for network: $network\n";
    push @threads, new threads (\&thread_entry, $np, $network);
    _log "DEBUG", "thread ".$threads[$#threads]->tid." created\n";
}

print "waiting\n";
$threads[0]->join;
print "joined\n";


exit 0;

sub thread_entry {
        my ($np, $network) = (shift, shift);

	# create thread-local connection to database. as of this writing,
	# still no way to share a common connection.

	my $dbh =  new NetPass::DB($cstr, $dbuser, $dbpass);
	die "unable to connect to database" unless defined $dbh;

	# fetch list of ports we "know" about from the config. we
	# use this list to quickly throw away data we aren't interested in

	my %ports;

	# pre-create the SNMP objects for speed. pre-fetch valid
	# ports, again, for speed.

# XXX over-ride dbh inside of np object?

	my %snmp;
	foreach my $switch (@{$np->cfg->getSwitches($network)}) {
	    foreach my $p (@{$np->cfg->configuredPorts($switch)}) {
		$ports{$p} = 1;
	    }
	    my ($r, $w) = $np->cfg->getCommunities($switch);
	    $snmp{$switch} = new NetPass::SNMP(-hostname  => $switch,
					       -community => $w
					      );
	}

	while ( 1 ) {
	    for my $switch (sort keys %snmp) {
		_log "DEBUG", "thread ".threads->self->tid. " wokeup\n";
		
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
			    if( !$dbh->macIsOK($mac) ) {
				$portIsOK = 0;
				push @nOkMacs, $mac;
			    } else {
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
				    _log("INFO", "Found OK mac $mac on multimac port $switch/$p\n");
				    $dbh->setMessage($mac, "multimac.html"),
				}
			    }
			    
			    _log("INFO", "Found unreg'd macs ".(join(',', sort @nOkMacs))." on $switch/$p\n");
			    $np->movePort(-switch => $switch,
					  -port   => $p,
					  -vlan   => 'bad');
			}
		    }
		}
	    }
	    sleep (10);
	}
}
