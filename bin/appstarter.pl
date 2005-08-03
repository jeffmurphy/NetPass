#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/appstarter.pl,v 1.4 2005/08/03 02:44:38 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


=head1 NAME

appstarter.pl - long running daemon that reads appstarter table and
performs actions such as starting and stopping pieces of the netpass
system.

=head1 SYNOPSIS

 appstarter.pl [-c cstr] [-U dbuser/dbpass] [-n] [-q] [-D] 
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging

=head1 OPTIONS

=over 8

=item B<-c cstr>

Specify an alternate NetPass DB connection string. The default is
"dbi:mysql:database=netpass" (DB on localhost). 

=item B<-U dbuser/dbpass>

Specify an alternate username/password to use to connect to the 
database. Default is "root" and no password.

=item B<-q>

Be quiet, don't print anything. Just exit with non-zero status if 
an error occurred. Otherwise, exit with zero status.

=item B<-n>

"Not really". Tell us what you will do, but don't really do it (this flag
negates the C<-q> flag)

=item B<-D> 

Enable debugging output. This flag causes this script to run in the foreground.
Otherwise, this script will detach and run in the background.

=back

=head1 DESCRIPTION

This script periodically scans the appwatcher table to see if anything
needs to be stopped, started or restarted. The table contains the application,
what to do and who to do it as. 

For example, if an admin updates a configuration parameter via the web interface,
the web UI might request that a certain component be restarted. Another example
is an Admin requesting that all ports be quarantined. This will lauch an app to
run in the background (because it takes a while). 

Sending an ALRM signal to this script will cause it to immediately read the table. Otherwise
it reads it once every 10 seconds.

=head1 APPLICATIONS

The following applications are recognized. Any other applications seen in the table
will be ignored.

 APPLICATION             WHAT WE CALL
 -------------------     ----------------------------
 httpd                   /etc/init.d/httpd
 nessusd                 /etc/init.d/nessusd
 squid                   /etc/init.d/squid
 resetport               /opt/netpass/bin/resetport.pl
 portmover               /opt/netpass/bin/portmover.pl
 macscan                 /opt/netpass/bin/macscan.pl
 netpass                 /etc/init.d/netpass
 npcfgd                  /opt/netpass/bin/npcfgd.pl
 npstatusd               /opt/netpass/bin/npstatusd.pl
 unquarall               /opt/netpass/bin/bulk_moveport.pl -N 0.0.0.0/0 -a unquarantine
 quarall                 /opt/netpass/bin/bulk_moveport.pl -N 0.0.0.0/0 -a quarantine
 reload_nessus_plugins   /opt/netpass/bin/update_nessus_plugins.sh
 reload_snort_plugins    /opt/netpass/bin/update_snort_plugins.sh

Items in the /etc/init.d directory must accept the "stop" "start" 
"restart" and "status" command line parameter and must do the appropriate thing.

All other items must gracefully DIE when a HUP is sent to them. If they
don't die within 5 seconds, a KILL will be sent. These items must also
write a pid file into the /var/run/netpass directory.

Finally, if those items fiddle with $0, it will be used to show status 
information (via the website, not this script, i'm just mentioning this
as an aside).



=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: appstarter.pl,v 1.4 2005/08/03 02:44:38 jeffmurphy Exp $

=cut


use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;
use Data::Dumper;

use POSIX qw(:sys_wait_h setsid setuid setgid);

use RUNONCE;
use NetPass::LOG qw(_log _cont);

my $myName = "appstarter";

my %opts;
getopts('c:U:qnDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize($myName, "/var/run/netpass");
}

if ($D) {
	NetPass::LOG::init *STDOUT;
} else {
	NetPass::LOG::init [ $myName, 'local0' ]; #*STDOUT;
}

my $otherPid = RUNONCE::alreadyRunning($myName);

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

require NetPass;
require NetPass::Config;

sub REAPER {
	my $child;
	while (($child = waitpid(-1,WNOHANG)) > 0) {
	}
	$SIG{'CHLD'} = \&REAPER;
}

$SIG{'ALRM'} = \&alarmHandler;
$SIG{'CHLD'} = \&REAPER; # just incase they fail to disassociate

print "new NP\n" if $D;

my $np = new NetPass(-cstr   => exists $opts{'c'} ? $opts{'c'} : undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

while (1) {
    _log ("DEBUG", "wakeup: processing worklist\n") if $D;

    RUNONCE::handleConnection();

    my $x = $np->db->getAppAction();
    if (ref($x) ne "ARRAY") {
	    _log("ERROR", "getAppAction failed: $x\n");
    } else {
	    _log("DEBUG", "Worklist: ". Dumper($x). "\n");

	    foreach my $row (@$x) {
		    if ($row->[2] eq "start") {
			    if (isRunning($row->[1])) {
				    _log("WARNING", $row->[1]. " is already running, so wont start another copy.\n");
				    # behavior is to ack the duplicate.XXX
			    } else {
				    start($row);
			    }
		    }
		    elsif ($row->[2] eq "stop") {
			    if (!isRunning($row->[1])) {
				    _log("WARNING", $row->[1]. " is not running, so cant stop.\n");
			    } else {
				    stop($row) unless !isRunning($row->[1]);
			    }
		    }
	    }
    }

    _log ("DEBUG", "sleeping for 10 seconds.\n") if $D;
    sleep(10);
}

sub isRunning {
	my $cn = shift;

	_log("DEBUG", "isRunning $cn\n") if $D;

	my @pids = ();

	if ($cn =~ /^([u]{0,1}[n]{0,1})quarall$/) {
		use Proc::ProcessTable;
		my $pt = new Proc::ProcessTable;
		my $un = $1;
		foreach my $pte (@{$pt->table}) {
			push @pids, $pte->pid 
			  if ($pte->cmndline =~ /^reset:\s${un}quarantine/);
		}
		_log("DEBUG", "isRunning looking for $cn found: ".join(',',@pids)."\n") if $D;
		return @pids;
	}
	_log("DEBUG", "shouldnt be here\n");
}


sub start {
	my $row = shift;
	my ($rowid, $cmd, $junk, $as) = @$row;

	if ($cmd eq "quarall") {
		runAs("/opt/netpass/bin/bulk_moveport.pl -N 0.0.0.0/0 -a   quarantine", $as);
	}
	elsif ($cmd eq "unquarall") {
		runAs("/opt/netpass/bin/bulk_moveport.pl -N 0.0.0.0/0 -a unquarantine", $as);
	}
}

sub stop {
	my $cmd = shift;
	if ($cmd eq "quarall") {
		# search for "reset: quarantine"
	} 
	elsif ($cmd eq "unquarall") {
		# search for "reset: unquarantine"
	}
}

sub runAs {
	my $cmd = shift;
	my $as  = shift;
	$as ||= "netpass";
	my ($uid,$gid) = (getpwnam($as))[2,3];
	if (!defined($uid)) {
		_log("ERROR", "no such user $as\n");
		return;
	}
	unless ($cmd) {
		_log("ERROR", "cmd empty\n");
		return;
	}

	_log("DEBUG", qq{exec'ing as $as cmd "$cmd"\n}) if $D;
	my $child = fork;
	return if ($child); # parent

	open STDIN, '/dev/null';
	open STDOUT, '>/dev/null';
	setsid;

	if (setgid($gid)) {
		_log("ERROR", "child $$ failed to setgid($gid) $!\n");
		exit 0;
	}
	if (setuid($uid)) {
		_log("ERROR", "child $$ failed to setuid($uid) $!\n");
		exit 0;
	}
	exec($cmd);
	_log("ERROR", "child $$ failed to exec($cmd) $!\n");
	exit 0;
}

exit 0;

# borrowed from mailgraph.pl

sub daemonize
{
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
