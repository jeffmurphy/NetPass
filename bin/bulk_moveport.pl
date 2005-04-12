#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/bulk_moveport.pl,v 1.3 2005/04/12 14:18:11 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

reset.pl - Reset Networks on the NetPass System

=head1 SYNOPSIS

 reset.pl [-c cstr] [-U dbuser/dbpass] <-N ip/mask> [-n] [-h] <-a action>
     -a	action		  actions are either quarantine or unquarantine
     -c	cstr	          db connect string
     -N ip/mask		  specify the ip and netmask of the network to have action performed on it  
     -n                   print actions that will be preformed without doing them 
     -h                   this message

=head1 DESCRIPTION

This script will move all ports, or a selected network of ports to either the
quarantine or unquarantine network. The correct VLAN ID, etc, will be derived
from the C<netpass.conf>. You can use "ps" to watch the process name. It should
update with the percentage complete.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: bulk_moveport.pl,v 1.3 2005/04/12 14:18:11 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use Pod::Usage;

use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass;
use NetPass::Config;

sub moveswitch ($$$$$$$);
sub getSwitchPortMap ($);

NetPass::LOG::init [ 'reset', 'local0' ]; #*STDOUT;

$SIG{CHLD} = "IGNORE";

my %opts;

getopts('U:DqnhN:c:a:', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};
pod2usage(2) if !exists $opts{'N'} || !exists $opts{'a'};

if ($opts{'a'} !~ /quarantine|unquarantine/) {
	printf "Error Invalid action %s\n", $opts{'a'};
	pod2usage(2);
}

if ($opts{'N'} !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}/) {
	printf "Error Invalid ip/mask %s\n", $opts{'N'};
	pod2usage(2);
}

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} : undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to create NetPass object" unless defined $np;

my $cfg = $np->cfg();
my $activate = exists $opts{'n'} ? 0 : 1; 

my $map = getSwitchPortMap($cfg);

_log "INFO", "reset ".$opts{'N'}." to ".$opts{'a'}." started\n";

if ($opts{'N'} eq '0.0.0.0/0') {
	my $networks = $cfg->getNetworks();

	foreach my $net (@$networks) {
		_log "INFO", "resetting $net to ".$opts{'a'}."\n";
		_log "INFO", "Forking to process $net for reset to ".$opts{'a'}."\n";

		printf("Forking to process %s\n", $net) unless $activate;
		defined (my $pid = fork) || die "Unable to fork, bailing out...";

		next if ($pid); # parent
        	my $switches     = $cfg->getSwitches($net);
		my $totports     = 0;
		my $doneports    = 0;

		map($totports += $#{$cfg->configuredPorts($_)}, @$switches);

        	foreach my $switch (@$switches) {
			moveswitch($np, $net, $switch, $map->{$switch},
				   $activate, \$doneports, $totports);
		}

		# child end
		exit 0;
	} 
	wait();

} else {
	_log "INFO", "resetting ".$opts{'N'}." to ".$opts{'a'}."\n";
	my $switches = $cfg->getSwitches($opts{'N'});
	my $totports;
	my $doneports = 0;
	map($totports += $#{$cfg->configuredPorts($_)}, @$switches);
	foreach my $switch (@$switches) { 
               moveswitch($np, $opts{'N'}, $switch, $map->{$switch},
			  $activate, \$doneports, $totports); 
        }
}

exit 0;

sub moveswitch ($$$$$$$) {
	my $np	      = shift;
	my $net       = shift;
	my $switch    = shift;
	my $ports     = shift;
	my $activate  = shift;
	my $doneports = shift;
	my $totports  = shift;

	_log "INFO", "processing switch $switch for reset to ".$opts{'a'}."\n";

	if (!defined $ports) {
		_log "ERROR", "switch $switch is not defined in vlanmap, skipping reset...\n";
		return 0;
	}

	my $counter = 0;
	foreach my $port (sort {$a <=> $b} @$ports) {
	        $counter++;
		if ($activate) {
			$np->movePort(-switch => $switch, -port => $port, -vlan => $opts{'a'});
		} else {
			printf("pid = %-6d moving switch %-15s port %-3d to %s\n",
				$$, $switch, $port, $opts{'a'});
		}

                $0 = sprintf("reset: %s %s %s%%", $opts{'a'}, $net,
                             int(($$doneports++/$totports) * 100));
	}
	return 1;
}

sub getSwitchPortMap ($) {
	my $cfg = shift;
	my $map = {};

	foreach my $s ($cfg->{'cfg'}->keys('vlanmap')) {
		$map->{$s} = $cfg->configuredPorts($s);	
	}
	return $map;
}
