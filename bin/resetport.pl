#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/resetport.pl,v 1.17 2005/09/19 15:26:56 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

resetport.pl - when we see a "linkdown" trap come in, reset to the port
so that it's back in the quarantine VLAN. when we see "linkup" optionally
set the client to unquar if they pass validation checks.

=head1 SYNOPSIS

 resetport.pl [-c cstr] [-U user/pass] [-t thread-queue-size] [-nqDh?] <traplog>
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging
     -c             db connect string
     -t             thread queue size
     -U user/pass   db user[/pass]

=head1 OPTIONS

=over 8

=item B<-q>

Be quiet, don't print anything. Just exit with non-zero status if 
an error occurred. Otherwise, exit with zero status.

=item B<-n>

"Not really". Tell us what you will do, but don't really do it (this flag
negates the C<-q> flag)

=item B<-c cstr>

DB do connect to.

=item B<-U user/pass>

Credentials to use when connect to DB.

=item B<-D> 

Enable debugging output. Runs script in the foreground. Otherwise script will
run in the background.

=item B<traplog> 

The log file of traps to watch. Log format should be (snmptrapd.conf entry):

 C<OPTIONS="-Lf /opt/netpass/log/snmptraps.log -p /var/run/snmptrapd.pid -F '%#04.4y-%#02.2m-%02.2l %#02.2h:%#02.2j:%#02.2k TRAP %N;%w;%q;%A;%v\n' ">

=item B<-t thead-queue-size>

A number denoting how many switches to delegate to each thread for monitoring.
The default is 20. If you have 100 switches in your NetPass configuration,
5 threads will be spawned. Each thread will handle incoming link up/down
processing.

Each thread requires a connection to the database, so don't set this number 
too low or you'll needless use DB resources.

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

$Id: resetport.pl,v 1.17 2005/09/19 15:26:56 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib/';
use FileHandle;
use Pod::Usage;
use IO::Seekable;
use File::Tail;
use threads;
use threads::shared;
use Data::Dumper;

use RUNONCE;

BEGIN {
    use Config;
    $Config{useithreads} or die "Recompile Perl with threads to run this program.";
}

my $otherPid = RUNONCE::alreadyRunning('resetport');

require NetPass;
use NetPass::LOG qw(_log _cont);

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}


my %opts;
getopts('vnqDt:c:U:h?', \%opts);
pod2usage(1) if $#ARGV != 0;
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

if (exists $opts{'D'}) {
	NetPass::LOG::init *STDOUT;
} else {
	NetPass::LOG::init [ 'resetport', 'local0' ];
}


my $fname = shift;

print "new NP..\n" if exists $opts{'D'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr   => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

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

# occasionally, you'll find a machine that will bring up link very early,
# but wont source any traffic until quite a bit later. in those cases,
# if we want to unquar-on-linkup, we cant. 
# so we stash the sw/port and re-try it later on. "later on" means
# "in 10 seconds". we'll keep trying every 10 seconds until we see
# a mac on the port. 

my $unq     = {};
my $quar    = {};
my $threads = {};
my $me      = threads->self;

my $ps = exists $opts{'t'} ? $opts{'t'} : 50;
my $threadPool = {};
my $swThrAffin = {};

_log("DEBUG", "creating $ps threads\n");

for (my $i = 0 ; $i < $ps ; $i++) {
	my %thrq : shared;
	$thrq{'q'}        = &share({});
	$thrq{'u'}        = &share({});
	$thrq{'workLoad'} = 0;
	share($thrq{'workLoad'});
	my $thr = new threads(\&thread_entry, \%thrq);
	my $tid = $thr->tid;
	$threadPool->{$tid} = {};
	$threadPool->{$tid}->{thro} = $thr;
	$threadPool->{$tid}->{thrq} = \%thrq;
}

_log("DEBUG", "parent entering endless loop\n");

while (1) {
	_log("DEBUG", $me->tid." parent awake. checking log file.\n");
	my @lines = ();
	while ($fh->predict == 0) {
		push @lines, $fh->read;
	}

        RUNONCE::handleConnection();
        processLines($np, $unq, $quar, \@lines);

	my $alreadyDidThisSwitch = {};

	foreach my $switch (keys %$unq, keys %$quar) {
		next if (exists $alreadyDidThisSwitch->{$switch});
		$alreadyDidThisSwitch->{$switch} = 1;

		_log("DEBUG", $me->tid." processing work read from log file\n");
		my $tid;

		# if this switch isnt being handled by an existing
		# thread, find a thread to handle it

		if (! exists($swThrAffin->{$switch}) ) {
			# find a thread to assign it to
			$tid = findThread($threadPool); 
			_log("DEBUG", $me->tid." findThread says to assign $switch to ".$tid."\n");
			$swThrAffin->{$switch} = $tid;
		} else {
			$tid = $swThrAffin->{$switch};
			_log("DEBUG", $me->tid." assigning work for $switch to $tid\n");
		}

		# add the work to the thread's queue

		_log("DEBUG", $me->tid." adding work (".join(',',@{$unq->{$switch}}).") to ".$tid."'s U queue\n")
		  if exists($unq->{$switch});
		_log("DEBUG", $me->tid." adding work (".join(',',@{$quar->{$switch}}).") to ".$tid."'s Q queue\n")
		  if exists($quar->{$switch});
		
		{
			lock(%{$threadPool->{$tid}->{'thrq'}});
			if (! exists $threadPool->{$tid}->{'thrq'}->{'u'}->{$switch}) {
				$threadPool->{$tid}->{'thrq'}->{'u'}->{$switch} = &share([]);
			}
			if (! exists $threadPool->{$tid}->{'thrq'}->{'q'}->{$switch}) {
				$threadPool->{$tid}->{'thrq'}->{'q'}->{$switch} = &share([]);
			}
			if ( exists $unq->{$switch} ) {
				push @{$threadPool->{$tid}->{'thrq'}->{'u'}->{$switch}}, @{$unq->{$switch}} 
				  if ($#{$unq->{$switch}} > -1);
				delete $unq->{$switch};
			}
			if ( exists $quar->{$switch} ) {
				push @{$threadPool->{$tid}->{'thrq'}->{'q'}->{$switch}}, @{$quar->{$switch}} 
				  if ($#{$quar->{$switch}} > -1);
				delete $quar->{$switch};
			}
		}
	}

	$me->yield;
	_log("DEBUG", $me->tid." parent done assigning work. sleeping.\n");
	sleep(11);
}

exit 0;

=head1 PROGRAMMERS DOC

=head2 Overview

This application is split into N threads. The main thread watches the
snmptrap.log file and parses new lines that appear in that file. If the
log entry indicates a link down trap, the main thread handles logging
the quarantine request to the database. 

If the log entry indicates a link up trap, the main thread will pass
that information (the switch and port) to a worker thread. It's the
job of the worker thread to watch the switch port for the appearance
of a MAC address, evaluate it and possibly unquarantine the port based
upon what the results of the MAC evaluation are.

=head2 findThread( )

Search through the available threads and select one to handle the (new)
switch. Right now, this is fairly simple, just add it to the thread that
has the least switches. In the future, we might want to track switch
time and avoid threads that are bogged down with slow switches.

=cut

sub findThread {
	my $tp = shift;

	my %qLens;
	my $firstSeen;

	foreach my $tid (keys %$tp) { 
		lock($tp->{$tid}->{thrq});
		$qLens{$tid} = $tp->{$tid}->{'thrq'}->{'workLoad'};
		$firstSeen = $tid unless $firstSeen;
	}

	my $assignToMe = '';
	my $min = '';

	foreach my $tid (keys %qLens) {
		if ( ($min eq '') || ($qLens{$tid} < $min ) ) {
			$assignToMe = $tid;
			$min = $qLens{$tid};
		}
	}

	return $assignToMe || $firstSeen;
}

=head2 removeFromQCheck($privQ, $privQT, $publicU, $switch)

Given the public unquarantine (linkup) queue and the private 
quarantine (linkdown) queue, private quarantine (linkdown) time
list and a switch:

if a port on the pub queue is also on the priv queue, remove 
it from the priv queue and remove it from the priv queue time.

=cut

sub removeFromQCheck {
	my $priv  = shift;
        my $privT = shift;
	my $pub   = shift;
	my $sw    = shift;

	return unless ( (ref($priv)  eq "HASH")  &&
			(ref($pub)   eq "HASH")  &&
			(ref($privT) eq "ARRAY") &&
			(exists $priv->{$sw})    &&
			(exists $pub->{$sw}) );

	# strip the ports from the priv queue

	foreach my $port (@{$pub->{$sw}}) {
		@{$priv->{$sw}} = grep !/^$port$/, @{$priv->{$sw}};
	}

	# remove any times that no longer have associated ports

	for (my $port = 1 ; $port <= $#{$privT->{$sw}} ; $port++) {
		$privT->{$sw}->[$port] = undef 
		  if (! grep /^$port$/, @{$priv->{$sw}});
	}
}

=head2 removeFromUCheck($privU, $publicQ, $switch)

Given the public quarantine (linkdown) queue and the private 
unquarantine (linkup) queue and a switch:

if a port on the pub queue is also on the priv queue, remove 
it from the priv queue.

=cut

sub removeFromUCheck {
	my $priv = shift;
	my $pub  = shift;
	my $sw   = shift;

	return unless ( (ref($priv) eq "HASH") &&
			(ref($pub)  eq "HASH") && 
			(exists $priv->{$sw})  &&
			(exists $pub->{$sw}) );

	# strip the ports from the priv queue

	foreach my $port (@{$pub->{$sw}}) {
		@{$priv->{$sw}} = grep !/^$port$/, @{$priv->{$sw}};
	}
}

=head2 thread_entry( )

This is the entry point for the worker threads. This routine sits
in an endless loop watching for new work to be placed on the
queue. When it sees new work, it moves it from the queue to a 
private queue. It then periodically calls procUQ() to process
the work. procUQ() will remove the work from the private queue
when it is finished, or leave it on the private queue if it 
was not able to process the work.

=cut

sub thread_entry {
	my $self     = threads->self;
	my $thrq     = shift;

	my $pq = { 
		  'q' =>  {},
		  'u' =>  {},
		  'qt' => {},
		  'ut' => {}
		 };

	print $self->tid(), " connecting to DB\n" if $opts{'D'};

	my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

	my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
			     -dbuser => $dbuser, -dbpass => $dbpass,
			     -debug  => exists $opts{'D'} ? 0 : 0, #XXX
			     -quiet  => exists $opts{'q'} ? 1 : 0);
	

	if (ref($np) ne "NetPass") {
    		_log("ERROR", "failed to connect to NetPass: $np\n");
		return;
	}


	while(1) {
		my $didWork = 0;
		{ 
			lock($thrq);

			my $wl = workLoad($pq);
			$thrq->{'workLoad'} = $wl;

			#print $self->tid, " wakeup wl=$wl\n"; 

			# move work to the private queues, deleting it from
			# the public queue. if the port is not already on
			# the linkdown queue, record the current time (and associate
			# it with the port) so we can implement the linkflap
			# tolerance feature.

			# the ports coming are guaranteed (by 'processLines') to be
			# unique. iow, you wont see the same port on both the 
			# linkup and linkdown queues. so...

			# if the port is on the private linkup queue, and we see
			# it on the public (newly detected) linkdown queue, then
			# remove it from the private linkup queue as link is now
			# down and we dont want to continue to process it as
			# if link is up. a port may persist on the linkup queue
			# for a while if unquar-on-linkup is enabled and no mac
			# has appeared on the port.

			# also, if the port is on the private linkdown queue, and
			# we see it on the public (newly detected) linkup queue then
			# remove it from the private linkdown queue. because link
			# is now up and we no longer want to process it for the 
			# linkdown event. ports may persist on the linkdown queue
			# for a while if linkflap tolerance is enabled.

			my $alreadyDidThisSwitch = {};

			foreach my $sw (keys %{$thrq->{'q'}}, keys %{$thrq->{'u'}}) {
				next if (exists $alreadyDidThisSwitch->{$sw});
				$alreadyDidThisSwitch->{$sw} = 1;

				if (! exists $pq->{'q'}->{$sw}) {
					$pq->{'q'}->{$sw}  = &share([]);
					$pq->{'qt'}->{$sw} = &share([]);
					$pq->{'u'}->{$sw}  = &share([]);
				}

				#print $self->tid, " sw=$sw moving u..\n";

				# run thru the new unquarantine ports (linkup ports)
				# and see if any of them are on the private 
				# linkdown queue. if they are, remove them from the
				# priv linkdown queue (quar 'q' queue)

				removeFromQCheck($pq->{'q'}, $pq->{'qt'}, 
						 $thrq->{'u'}, $sw);

				# run thru the new quarantine ports (linkdown ports)
				# and see if any of them are on the private 
				# linkup queue. if they are, remove them from the
				# priv linkup queue (unquar 'u' queue)

				removeFromUCheck($pq->{'u'}, $thrq->{'q'}, $sw);

				# push the port onto the unquarantine work queue
				# for this switch and then uniq that queue to remove
				# duplicates. empty the public queue.

				push @{$pq->{'u'}->{$sw}}, @{$thrq->{'u'}->{$sw}};
				$pq->{'u'}->{$sw} = uniq($pq->{'u'}->{$sw});
				$thrq->{'u'}->{$sw} = &share([]);

				# push the port onto the quarantine work queue
				# for this switch. if the port wasn't already on
				# the queue, record the current time so we can
				# to the linkflap tolerance feature. empty the 
				# public queue.

				#print $self->tid, " sw=$sw moving q..\n";

				($pq->{'q'}->{$sw},
				 $pq->{'qt'}->{$sw})
				  = linkflap_starttime_calculation($pq->{'q'}->{$sw},
								   $pq->{'qt'}->{$sw},
								   $thrq->{'q'}->{$sw});

				$pq->{'q'}->{$sw} = uniq($pq->{'q'}->{$sw});
				$thrq->{'q'}->{$sw} = &share([]);
				$pq = procUQ($pq, $np);
			}

		}
		sleep(10) unless $didWork;
	}
}

sub linkflap_starttime_calculation {
	my $priv = shift; # private queue (arrayref)
	my $ptl  = shift; # port time list (arrayref)
	my $pub  = shift; # public queue (arrayref)

	return undef unless (ref($priv) eq "ARRAY");
	return undef unless (ref($ptl)  eq "ARRAY");
	return undef unless (ref($pub)  eq "ARRAY");

	foreach my $port (@{$pub}) {
		if (grep (/^$port$/, @{$priv})) {
			# port is already on the list
		} else {
			# record the time at which we added
			# this port to the queue
			$ptl->[$port] = time();
			push @{$priv}, $port;
		}
	}

	return ($priv, $ptl);
}


sub uniq {
        my $ar = shift;
        return unless (ref($ar) eq "ARRAY");
        my %h = map { $_ => $_ } @{$ar};
        $ar = [ sort keys %h ];
        return $ar;
}

sub workLoad {
	my $pq = shift;
	my $wl = 0;
	if (ref($pq) eq "HASH") {
		foreach my $sw (keys %{$pq->{'u'}}) {
			$wl += @{$pq->{'u'}->{$sw}};
		}
		foreach my $sw (keys %{$pq->{'q'}}) {
			$wl += @{$pq->{'q'}->{$sw}};
		}
	}
	return $wl;
}

=head2 processLines(\@lines)

This routine will take an array ref containing lines read from the file
and will parse them. For lines that show linkdown, we will place them
on the work queue to be delegated to a thread for handling. 

For lines that show linkup, we'll place them on the work queue
if unquar-on-linkup is set.

Periodically, that list will be processed by another routine.

=cut

sub processLines {
	my ($np, $unq, $quar) = (shift, shift, shift);
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
				_log("WARNING", "cant parse port out of \"$_port\"\n")
				  unless exists $opts{'q'};
				next;
			}
			
			_log("DEBUG", "$switch/$port checking if resetport is enabled...\n") if exists $opts{'D'};
			if (resetPortEnabled($np, $switch, $port) == 0) {
				_log("DEBUG", "$switch/$port reset port is disabled for $switch $port. skipping.\n");
				next;
			}
			_log("DEBUG", "$switch/$port yes, reserport is enabled and ttype=$ttype\n") if exists $opts{'D'};

			if ($ttype == 2) { # LINKDOWN
				_log("INFO", "$switch/$port LINKDOWN\n");

				# if the port is already on the linkup queue, remove it from that 
				# queue (because this event - linkdown - occurred at a later time)

				@{$unq->{$switch}} = grep !/^$port$/, @{$unq->{$switch}} if (exists ($unq->{$switch}));
				$quar->{$switch} = [] if (!exists($quar->{$switch}));
				push @{$quar->{$switch}}, $port;
			}
			
			elsif ($ttype == 3) { # LINKUP
				_log("INFO", "$switch/$port LINKUP\n");

				# if the port is already on the linkdown queue, remove it from that
				# queue (because this event - linkdown - occurred at a later time

				@{$quar->{$switch}} = grep !/^$port$/, @{$quar->{$switch}} if (exists ($quar->{$switch}));
				$unq->{$switch} = [] if (!exists($unq->{$switch}));
				push @{$unq->{$switch}}, $port;
			}
		}
	}
}

=head2 procUQ($np, $uq, $uqsetting)

This routine will run the list of ports-to-be-possibly-unquarantined
and will unquarantine those that should be. Those that shouldnt be
will be left alone (we assume the port is currently quarantined). 

Those that we cant make a decision on (because the port doesnt
show any attached macs) will be left on the list and reviewed
again the next time we are called.

A port will be reviewed for a maximum of 1 hour. If we don't see a MAC
appear in that time, we stop looking.

=cut

# 

sub procUQ {
	my $pq = shift;
	my $np = shift;

	my $self = threads->self;

	# process unquarantine (linkup) events

	my $switches = uniq [ keys %{$pq->{'u'}}, keys %{$pq->{'q'}} ];

	foreach my $switch (@$switches) {
		my $cn = ($np->cfg->getCommunities($switch))[1];

		my $failed = {};

		next if (!exists($pq->{'u'}->{$switch}) && !exists($pq->{'q'}->{$switch}));
		next if (($#{$pq->{'u'}->{$switch}} == -1) && ($#{$pq->{'q'}->{$switch}} == -1));

                my $snmp = new SNMP::Device('hostname'       => $switch,
                                            'snmp_community' => $cn);
                my ($mp, $pm) = $snmp->get_mac_port_table();

		if (exists ($pq->{'u'}->{$switch})) {
			foreach my $port (@{$pq->{'u'}->{$switch}}) {

				# if the port is on the 'q' queue, remove it from that queue since
				# link is now, apparently, up.

				if (exists ($pq->{'q'}->{$switch})) {
					_log("DEBUG", $self->tid(). " $switch $port possibly removing from 'q'\n");
					@{$pq->{'q'}->{$switch}} = grep !/^$port$/, @{$pq->{'q'}->{$switch}};
					if (exists ($pq->{'qt'}->{$switch})) {
						$pq->{'qt'}->{$switch}->[$port] = undef;
					}
				}

				my $unq_on_linkup = $np->cfg->policy(-key => 'UNQUAR_ON_LINKUP') || "0";
				my $rppt = $np->cfg->policy(-key => 'RESETPORT_PORT_POLL_TIME') || 0;
				
				# if possible, we'll resolve the switch/port to a specific network and the
				# look to see if the above policy settings are over-ridden at the network or
				# netgroup level.
				
				my $curNw = $np->cfg->getMatchingNetwork(-switch => $switch, -port => $port);
				if ($curNw =~ /^\d/) {
					_log("DEBUG", $self->tid(). " sw=$switch po=$port nw=$curNw\n");
					$unq_on_linkup = $np->cfg->policy(-key => 'UNQUAR_ON_LINKUP',     -network => $curNw);
					$rppt          = $np->cfg->policy(-key => 'RESETPORT_PORT_POLL_TIME', -network => $curNw);
				}
				
				# figure out what macs are on this port
				
				_log("DEBUG", $self->tid. " link up $switch $port and unq_lu=$unq_on_linkup rppt=$rppt\n");
				
				print $self->tid. " fetch maclist\n" if exists $opts{'D'};
				
				if (!exists ($failed->{$switch})) {
					$failed->{$switch} = [];
					$failed->{$switch."PT"} = [];
				}
				
				my $macList = $pm->{$port};
				if (!defined($macList)) {
					_log ("ERROR", $self->tid(). 
					      " we want to unquar on linkup, but $switch doesnt have mac information available for port $port yet!\n");
					push @{$failed->{$switch}}, $port;
					$failed->{$switch."PT"}->[$port] = time(); #XXX
					next;
				}
				
				print "macList=".join(',', @$macList)."\n" if exists $opts{'D'};
				
				if ($unq_on_linkup eq "1") {
					print $self->tid(), " unq=ON findRegMac\n" if exists $opts{'D'};
					
					# in order to move the port to unquarantine
					# we just need to call validateMac on the first
					# registered mac address we found. 
					
					my ($regMac, $regMacStatus) = findRegMac($np, $macList);
					if (!defined($regMac)) {
						_log ("WARNING", $self->tid(). " no macs registered on $switch $port. leaving in quarantine.\n");
					} else {
						_log("DEBUG",  $self->tid(). " regMac $regMac $regMacStatus\n") if exists $opts{'D'};
						
						_log ("DEBUG", $self->tid(). " found a registered mac ($regMac) on $switch $port\n");
						# if we are alone on this port, and are UNQUAR
						# then unquarantine us
						
						if ($#{$macList} == 0) {
							_log ("DEBUG", $self->tid(). " $regMac is alone on $switch $port. status is $regMacStatus\n");
							if ($regMacStatus =~ /UNQUAR$/) {
								_log ("DEBUG", $self->tid(). " $regMac unquarantine $switch $port\n");
								if(exists $opts{'n'}) {
									_log("DEBUG", $self->tid(). " not really!\n");
								} else {
									$np->db->requestMovePort(-switch => $switch, -port => $port, 
												 -vlan => 'unquarantine', -by => 'resetport.pl') ||
												   push @{$failed->{$switch}}, $port;
								}
							} else {
								_log ("DEBUG", $self->tid(). " $regMac leave quar $switch $port\n");
							}
						} else {
							# if we are not alone, then enforceMultiMacPolicy
							# and do whatever it says to do (quar or unquar)
							
							_log ("DEBUG", $self->tid(). " $switch $port has more than one mac on it. enforceMultiMacPolicy\n");
							
							my ($_rv, $_sw, $_po) = $np->enforceMultiMacPolicy($regMac, '', $regMacStatus, 
													   $switch, $port, 
													   undef, {$port => $macList});
							if ($_rv =~ /UNQUAR$/) {
								_log ("DEBUG", $self->tid(). " $switch $port multiMac said to unquarantine the port.\n");
								if (exists $opts{'n'}) {
									_log("DEBUG", "not really!\n");
								} else {
									$np->db->requestMovePort(-switch => $switch, -port => $port, 
												 -vlan => 'unquarantine', -by => 'resetport.pl') ||
												   push @{$failed->{$switch}}, $port;
								}
							} else {
								_log ("DEBUG", $self->tid()." $switch $port multiMac said to quarantine the port.\n");
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
					
					my $numOK   = $np->db->UQLinkUp_itDependsCheck($macList);
					my $mmpol   = $np->cfg->policy(-key => 'MULTI_MAC');
					
					if ( ($numOK == ($#$macList+1)) && ($mmpol eq "ALL_OK") ) {
						_log ("DEBUG", $self->tid()." $switch $port 'itdepends' set. everything looks good. unquar port. ",
						      "numOK=$numOK numMacs=".($#$macList+1)." mmpol=$mmpol\n");
						if (exists $opts{'n'}) {
							_log("DEBUG", $self->tid(). " not really!\n");
						} else {
							$np->db->requestMovePort(-switch => $switch, 
										 -port => $port, 
										 -vlan => 'unquarantine',
										 -by => 'resetport.pl') ||
										   push @{$failed->{$switch}}, $port;
						}
					} else {
						_log ("DEBUG", $self->tid()." $switch $port 'itdepends' set. somethings not right. quar port. ",
						      "numOK=$numOK numMacs=".($#$macList+1)." mmpol=$mmpol maclist=(",
						      join(',', @$macList),
						      ")\n");
					}
				}
			}

			if (exists $pq->{'q'}->{$switch}) {
				foreach my $port (@{$pq->{'q'}->{$switch}}) {
					my $unq_on_linkup = $np->cfg->policy(-key => 'UNQUAR_ON_LINKUP') || "0";
					my $rppt = $np->cfg->policy(-key => 'RESETPORT_PORT_POLL_TIME') || 0;
                                        my $lftol = $np->cfg->policy(-key => 'LINKFLAP_TOLERANCE') || 0;
					
					# if possible, we'll resolve the switch/port to a specific network and the
					# look to see if the above policy settings are over-ridden at the network or
					# netgroup level.
					
					my $curNw = $np->cfg->getMatchingNetwork(-switch => $switch, -port => $port);
					if ($curNw =~ /^\d/) {
					        _log("DEBUG", $self->tid(). " sw=$switch po=$port nw=$curNw\n");
					        $unq_on_linkup = $np->cfg->policy(-key => 'UNQUAR_ON_LINKUP',     -network => $curNw);
				        	$rppt          = $np->cfg->policy(-key => 'RESETPORT_PORT_POLL_TIME', -network => $curNw);
                                                $lftol         = $np->cfg->policy(-key => 'LINKFLAP_TOLERANCE', -network => $curNw) || 0;
				        }
				
				       _log("DEBUG", $self->tid. " link down $switch $port and unq_lu=$unq_on_linkup rppt=$rppt\n");
				
					# if we have a link flap tolerance time set, dont do anything until the time has
					# expired. if link comes back up on the port before the time expires, the port
					# will be removed from the 'q' queue by the linkup code above. if the timer
					# expires, quarantine the port.

					if ($rppt) {
						if ($pq->{'qt'}->{$switch}->[$port]) {
							# if we are on the 'u' list then link is up and we'll be
							# removed from the 'u' list by the linkup code above.

							# if the timer has expired, tho, we should quarantine this port.
							# otherwise leave the port on the 'q' list

							if (  time() - $pq->{'qt'}->{$switch}->[$port] > $lftol ) {

								$np->db->requestMovePort(-switch => $switch, -port => $port, 
											 -vlan => 'quarantine', 
											 -by => 'resetport.pl') ||
											   _log("ERROR", $np->db->error());
								_log ("DEBUG", $self->tid()." quarantined $switch $port because rppt expired\n") 
								  if exists $opts{'D'};
								
								# remove the port from the linkdown queue since we've processed it

								@{$pq->{'q'}->{$switch}} = grep /!$port$/, @{$pq->{'q'}->{$switch}};
								$pq->{'qt'}->{$switch}->[$port] = undef;
							} else {
								_log ("DEBUG", $self->tid(). 
								      " $switch $port has linkdown, but is recent, we'll wait a while: ".
								      (time() - $pq->{'qt'}->{$switch}->[$port])." secs old (of $lftol max)\n");
							}
						} else {
							_log ("DEBUG", $self->tid()." $switch $port has no first-seen time, but should.\n");
							$pq->{'qt'}->{$switch}->[$port] = time();
						}
					} else {
						# rppt is not set (or set to zero) so immediate quarantine the port

						$np->db->requestMovePort(-switch => $switch, -port => $port, 
									 -vlan => 'quarantine', 
									 -by => 'resetport.pl') ||
									   _log("ERROR", $np->db->error());
						_log ("DEBUG", $self->tid()." immediately quarantined $switch $port because rppt=0\n") 
						  if exists $opts{'D'};

						# remove the port from the linkdown queue since we've processed it
						
						@{$pq->{'q'}->{$switch}} = grep /!$port$/, @{$pq->{'q'}->{$switch}};
						$pq->{'qt'}->{$switch}->[$port] = undef;
                                       }
				}
			}

			# save the ports that have failed so we can take care of 
			# them next time around. since this is our private queue,
			# no need to share it.
			
			if (exists $failed->{$switch}) {
				@{$pq->{'u'}->{$switch}} = @{$failed->{$switch}};
			} else {
				$pq->{'u'}->{$switch} = [];
			}
	      }

	} # end foreach 

	return $pq;
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

	return $np->cfg->policy(-key => 'resetport', -network => $_nw);
}

sub findRegMac {
	my $np = shift;
	my $ml = shift;
	foreach my $m ( @$ml ) {
		my $ms = $np->db->macStatus($m);
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
