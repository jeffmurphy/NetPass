#!/usr/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/resetport.pl,v 1.3 2004/10/01 15:40:50 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

resetport.pl - when we see a "linkdown" trap come in, reset to the port
so that it's back in the quarantine VLAN. when we see "linkup" optionally
set the client to unquar if they pass validation checks.

=head1 SYNOPSIS

 resetport.pl [-n] [-q] [-D] <traplog>
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging
     -c             netpass.conf location

=head1 OPTIONS

=over 8

=item B<-q>

Be quiet, don't print anything. Just exit with non-zero status if 
an error occurred. Otherwise, exit with zero status.

=item B<-n>

"Not really". Tell us what you will do, but don't really do it (this flag
negates the C<-q> flag)

=item B<-c>

location of C<netpass.conf> - defaults to /opt/netpass/etc/netpass.conf

=item B<-D> 

Enable debugging output. Runs script in the foreground. Otherwise script will
run in the background.

=item B<traplog> 

The log file of traps to watch. Log format should be (snmptrapd.conf entry):

 C<OPTIONS="-Lf /opt/netpass/log/snmptraps.log -p /var/run/snmptrapd.pid -F '%#04.4y-%#02.2m-%02.2l %#02.2h:%#02.2j:%#02.2k TRAP %N;%w;%q;%A;%v\n' ">

=back

=head1 DESCRIPTION

This script watches incoming traps and resets the port to the quarantine VLAN when a 
linkdown trap is received. It's possible to have snmptrapd call the script directly,
but according to the documentation, it does so synchronously and waits while the 
script runs. Since that raises concerns about the script taking too long and causing
snmptrapd to miss incoming traps, we do it this way. At least we'll have a good
audit trail.

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: resetport.pl,v 1.3 2004/10/01 15:40:50 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib/';
use FileHandle;
use Pod::Usage;
use IO::Seekable;
use File::Tail;

use RUNONCE;

my $otherPid = RUNONCE::alreadyRunning('resetport');

require NetPass;
use NetPass::LOG qw(_log _cont);
require NetPass::Config;

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}


my %opts;
getopts('vnqDc:h?', \%opts);
pod2usage(1) if $#ARGV != 0;
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

if (exists $opts{'D'}) {
	NetPass::LOG::init *STDOUT;
} else {
	NetPass::LOG::init [ 'resetport', 'local0' ];
}


my $fname = shift;

print "new NP ", (exists $opts{'c'} ? $opts{'c'} : "[default conf]"), "\n" if exists $opts{'D'};

my $np = new NetPass(-config => defined $opts{'c'} ? $opts{'c'} :
		     "/opt/netpass/etc/netpass.conf",
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

if (!defined($np)) {
    _log "ERROR", "failed to create NetPass object\n";
    exit 255;
}


print "DB connect\n" if $opts{'D'};

my $dbh = new NetPass::DB($np->cfg->dbSource,
                          $np->cfg->dbUsername,
                          $np->cfg->dbPassword,
                          1);

if (!defined($dbh)) {
    my $e = "failed to create NP:DB ".DBI->errstr."\n";
    _log "ERROR", $e;
    print $e;
    exit 255;
}

print "new File::Tail\n" if exists $opts{'D'};

my $fh = new File::Tail (name        => $fname,
			 interval    => 3,
			 maxinterval => 5);

if( !defined($fh) ) {
    _log "ERROR", "can't open file <$fname>: $!\n";
    die "cant open file <$fname>: $!";
}

print "running in foreground (no daemon)\n" if exists $opts{'D'};

daemonize("resetport", "/var/run/netpass") unless exists $opts{'D'};

print "entering while..\n" if exists $opts{'D'};

my $unq_on_linkup = $np->cfg->policy('UNQUAR_ON_LINKUP') || "0";

# occasionally, you'll find a machine that will bring up link very early,
# but wont source any traffic until quite a bit later. in those cases,
# if we want to unquar-on-linkup, we cant. 
# so we stash the sw/port and re-try it later on. "later on" means
# "in 10 seconds". we'll keep trying every 10 seconds until we see
# a mac on the port. 

my $unq = {};

while (1) {
	my @lines = ();
	while ($fh->predict == 0) {
		push @lines, $fh->read;
	}
	RUNONCE::handleConnection();
	processLines($np, $dbh, $unq, 
		     $np->cfg->policy('UNQUAR_ON_LINKUP') || "0", 
		     \@lines);
	procUQ($np, $dbh, $unq, 
	       $np->cfg->policy('UNQUAR_ON_LINKUP') || "0");

	sleep(10);
}

exit 0;

=head1 PROGRAMMERS DOC

=head2 processLines(\@lines)

This routine will take an array ref containing lines read from the file
and will parse them. For lines that show linkdown, we will immediately
quarantine the port. For lines that show linkup, we'll stash the
switch/port into a work-list ($unq) if unquar-on-linkup is set. 

Periodically, that list will be processed by another routine.

=cut

sub processLines {
	my ($np, $dbh, $unq) = (shift, shift, shift);
	my $unq_on_linkup = shift;
	my $lines = shift;

	while (defined(my $l = shift @{$lines})) {
		chomp $l;
		
		if ($l !~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/) {
			_log("ERROR", "Line looks funny, skipping: \"$l\"\n");
			next;
		}
		my @p = split(/\s/, $l);
		
		if ($#p < 4) {
			_log ("ERROR", "Line doesnt split into 4 or more parts: \"$l\"\n");
		} else {
			my ($dt, $tm) = ($p[0], $p[1]);
			
			@p = split(/;/, $l);
			
			if (($#p < 2) || !defined($p[1]) || !defined($p[2]) || !defined($p[3])) {
				_log("ERROR", "could not split \"$l\" around semi into 3 parts\n");
				next;
			}
			
			my ($ttype, $switch, $_port) = ($p[1], $p[3], $p[4]);
			my $port;
			if ($_port  =~ /ifIndex.(\d+)\s/) {
				$port = $1;
			} else {
				print "cant parse port out of \"$_port\". skip\n"
				  if exists $opts{'D'};
				_log("ERROR", "cant parse port out of \"$_port\"\n");
				next;
			}
			
			_log("DEBUG", "checking if resetport is enabled...\n") if exists $opts{'D'};
			if (resetPortEnabled($np, $switch, $port) == 0) {
				_log("DEBUG", "reset port is disabled for $switch $port. skipping.\n");
				next;
			}
			_log("DEBUG", "yes it is...\n") if exists $opts{'D'};
			
			_log("DEBUG", "ttype=$ttype sw=$switch port=$port\n") if exists $opts{'D'};
			
			if ($ttype == 2) { # LINKDOWN
				_log("INFO", "LINKDOWN quarantine $switch / $port\n");

				# if the link is down, and this port is on our linkup worklist, 
				# remove it.

				if (exists $unq->{$switch}) {
					my @pl = grep {!/^$port$/} @{$unq->{$switch}};
					$unq->{$switch} = [ @pl ];
				}

				if (exists $opts{'n'}) {
					_log("DEBUG", " not really!\n") if exists $opts{'D'};
					_log("INFO", "-n flag given. not really doing it.\n"); 
				} else {
					$dbh->requestMovePort(-switch => $switch, -port => $port, 
							      -vlan => 'quarantine', 
							      -by => 'resetport.pl') ||
								_log("ERROR", $dbh->error());
					_log ("DEBUG", " backfrom dbh->requestMovePort\n") 
					  if exists $opts{'D'};
				}
			}
			
			elsif (($ttype == 3) && ($unq_on_linkup ne "0")) { # LINKUP
				_log("INFO", "LINKUP (maybe) unquarantine $switch / $port\n");

				# just record the switch, port. we process quar-on-linkup in a separate
				# routine
				
				if ( exists($unq->{$switch}) && (!grep {/^$port/} @{$unq->{$switch}}) ) {
					push @{$unq->{$switch}}, $port;
				} else {
					$unq->{$switch} = [ $port ];
				}
			}
		}
	}
}

=head2 procUQ($np, $dbh, $uq, $uqsetting)

This routine will run the list of ports-to-be-possibly-unquarantined
and will unquarantine those that should be. Those that shouldnt be
will be left alone (we assume the port is currently quarantined). 

Those that we cant make a decision on (because the port doesnt
show any attached macs) will be left on the list and reviewed
again the next time we are called.

=cut

sub procUQ {
	my $np = shift;
	my $dbh = shift;
	my $uq = shift;
	my $unq_on_linkup = shift;

	my $numSwitches = keys %{$unq};

	foreach my $switch (keys %{$unq}) {
		my @failed = ();
		_log("DEBUG", $numSwitches, " / ",
		     ($#{$unq->{$switch}}+1)." ports on this switch to process\n");
		foreach my $port (@{$unq->{$switch}}) {
			# figure out what macs are on this port
			
			_log("DEBUG", "link up $switch $port and unq_lu is $unq_on_linkup\n");
			
			print "fetch maclist ($unq_on_linkup)\n" if exists $opts{'D'};
			my $macList = getMacList($np, $switch, $port);
			if (!defined($macList)) {
				_log ("ERROR", "we want to unquar on linkup, but $switch doesnt have mac information available for port $port yet!\n");
				push @failed, $port;
				next;
			}
			
			print "macList=".join(',', @$macList)."\n" if exists $opts{'D'};
			
			if ($unq_on_linkup eq "1") {
				print "unq=ON findRegMac\n" if exists $opts{'D'};
				
				# in order to move the port to unquarantine
				# we just need to call validateMac on the first
				# registered mac address we found. 
				
				my ($regMac, $regMacStatus) = findRegMac($dbh, $macList);
				if (!defined($regMac)) {
					_log ("WARNING", "no macs registered on $switch $port. leaving in quarantine.\n");
				} else {
					_log("DEBUG",  "regMac $regMac $regMacStatus\n") if exists $opts{'D'};
					
					_log ("DEBUG", "found a registered mac ($regMac) on $switch $port\n");
					# if we are alone on this port, and are UNQUAR
					# then unquarantine us
					
					if ($#{$macList} == 0) {
						_log ("DEBUG", "$regMac is alone on $switch $port. status is $regMacStatus\n");
						if ($regMacStatus =~ /UNQUAR$/) {
							_log ("DEBUG", "$regMac unquarantine $switch $port\n");
							if(exists $opts{'n'}) {
								_log("DEBUG", "not really!\n");
							} else {
								$dbh->requestMovePort(-switch => $switch, -port => $port, 
										      -vlan => 'unquarantine', -by => 'resetport.pl') ||
											push @failed, $port;
							}
						} else {
							_log ("DEBUG", "$regMac leave quar $switch $port\n");
						}
					} else {
						# if we are not alone, then enforceMultiMacPolicy
						# and do whatever it says to do (quar or unquar)
						
						_log ("DEBUG", "$switch $port has more than one mac on it. enforceMultiMacPolicy\n");
						
						my ($_rv, $_sw, $_po) = $np->enforceMultiMacPolicy($dbh, $regMac, '', $regMacStatus, 
												   $switch, $port, 
												   undef, {$port => $macList});
						if ($_rv =~ /UNQUAR$/) {
							_log ("DEBUG", "$switch $port multiMac said to unquarantine the port.\n");
							if (exists $opts{'n'}) {
								_log("DEBUG", "not really!\n");
							} else {
								$dbh->requestMovePort(-switch => $switch, -port => $port, 
										      -vlan => 'unquarantine', -by => 'resetport.pl') ||
											push @failed, $port;
							}
						} else {
							_log ("DEBUG", "$switch $port multiMac said to quarantine the port.\n");
						}
						
					}
					
				}
			} 
			elsif($unq_on_linkup =~ /^ITDEPENDS$/) {
				# "ITDEPENDS" means that in order to unquarantine this port
				# the following must be true:
				#
				# if MULTI_MAC is ALL_OK then
				#     all of the clients on this port must be tagged as uqlinkup="yes" 
				#     AND they all must be registered and P/UNQUAR. UQLinkUp_itDepends()
				#     does this in a single query. 
				# else
				# XXX we're not going to implement the other MULTI_MAC cases yet
				# endif
				
				my $numOK   = $dbh->UQLinkUp_itDependsCheck($macList);
				my $mmpol   = $np->cfg->policy('MULTI_MAC');
				
				if ( ($numOK == ($#$macList+1)) && ($mmpol eq "ALL_OK") ) {
					_log ("DEBUG", "$switch $port 'itdepends' set. everything looks good. unquar port. ",
					      "numOK=$numOK numMacs=".($#$macList+1)." mmpol=$mmpol\n");
					if (exists $opts{'n'}) {
						_log("DEBUG", "not really!\n");
					} else {
						$dbh->requestMovePort(-switch => $switch, 
								      -port => $port, 
								      -vlan => 'unquarantine',
								      -by => 'resetport.pl') ||
									push @failed, $port;
					}
				} else {
					_log ("DEBUG", "$switch $port 'itdepends' set. somethings not right. quar port. ",
					      "numOK=$numOK numMacs=".($#$macList+1)." mmpol=$mmpol maclist=(",
					      join(',', @$macList),
					      ")\n");
				}
			}
		}
		if ($#failed == -1) {
			delete $unq->{$switch};
		} else {
			# save them for the next run
			$unq->{$switch} = [ @failed ];
		}
	}
}


=head2 0 | 1 = resetPortEnabled($np, $sw, $po)

Given a switch and port, determine what network the port is on. Look in the 
<network> clause and see if 'resetport' = 'on' if it is, return 1.  if
'resetport' doesnt exist in the <network> clause, look for a global setting
in the <policy>. if it is globally on, return 1.

in any other case, return 0.

=cut


sub resetPortEnabled {
	my ($np, $sw, $po) = (shift, shift, shift);

	# figure out what vlan the port is a member of

	my @vl = $np->cfg->availableVlans(-switch => $sw, -port => $po);

	if (!@vl || ($#vl == -1) || !defined($vl[0])) {
		_log("ERROR", "$sw $po isnt in the <vlanmap>!\n");
		return 0;
	}

	if ($#vl != 1) {
		_log("ERROR", "$sw $po has more than 2 vlans mapped to it in <vlanmap>? ",
		     "#vl=", $#vl, " ", join(',', @vl), "\n");
		return 0;
	}

	# figure out what network this switch is serviced by

	my $_nw = undef;

	foreach my $nw (@{$np->cfg->getNetworks()}) {
		my @sl = $np->cfg->availableVlans(-network => $nw);
		if ( $#sl != 1 ) {
			_log("ERROR", "either $nw has no vlans specified, or doesnt have exactly 2 specified. punt.\n");
			return 0;
		}

		my $test = $sl[0];
		if (grep {/^$sl[0]$/} @vl) {
			$_nw = $nw;
			last;
		}

		#_log ("WARNING", "skip/no-intersect $sw $po vl=", join(',', @vl), " nw=$nw nvl=", join(',', @sl), "\n");

	}

	if (!defined($_nw)) {
		_log ("ERROR", "$sw $po has no matching network (searched by vlan)\n");
		return 0;
	}

	# is RESETPORT enabled on this network?

	return $np->cfg->resetportSetting($_nw);
}

sub getMacList {
	my ($np, $sw, $po) = (shift, shift, shift);
	my $cn = ($np->cfg->getCommunities($sw))[1];
	if (!defined($cn)) {
		_log ("ERROR", "failed to get community name for $sw\n");
		return undef;
	}
	my $snmp = new SNMP::Device('hostname'       => $sw, 
				    'snmp_community' => $cn);
	my ($mp, $pm) = $snmp->get_mac_port_table();
	return $pm->{$po};
}

sub findRegMac {
	my $dbh = shift;
	my $ml = shift;
	foreach my $m ( @$ml ) {
		my $ms = $dbh->macStatus($m);
		return (NetPass::padMac($m), $ms) if defined($ms);
	}
	return undef; # no macs were registered
}

# borrowed from mailgraph.pl

sub daemonize
{
    use POSIX 'setsid';

    my ($myname, $pidDir) = (shift, shift);
    chdir $pidDir or die "$myname: can't chdir to $pidDir: $!";
    -w $pidDir or die "$myname: can't write to $pidDir\n";

    open STDIN, '/dev/null' or die "$myname: can't read /dev/null: $!";
    open STDOUT, '>/dev/null'
      or die "$myname: can't write to /dev/null: $!";

    defined(my $pid = fork) or die "$myname: can't fork: $!";
    if($pid) {
	# parent
	my $pidFile = $pidDir . "/" . $myname . ".pid";
	open PIDFILE, "> " . $pidFile
	  or die "$myname: can't write to $pidFile: $!\n";
	print PIDFILE "$pid\n";
	close(PIDFILE);
	exit 0;
    }
    # child
    setsid                  or die "$myname: can't start a new session: $!";
    open STDERR, '>&STDOUT' or die "$myname: can't dup stdout: $!";
}
