#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/appstarter.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


=head1 NAME

appstarter.pl - long running daemon that reads appstarter table and
performs actions such as starting and stopping pieces of the netpass
system.

=head1 SYNOPSIS

 appstarter.pl [-c config] [-n] [-q] [-D] 
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging

=head1 OPTIONS

=over 8

=item B<-c configFile>

Specify an alternate NetPass configuration file. The default is
C</opt/netpass/etc/netpass.conf>

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
 npsnortd                /opt/netpass/bin/npsnortd.pl
 unquar-all              /opt/netpass/bin/unquar-all.pl
 quar-all                /opt/netpass/bin/quar-all.pl

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

$Id: appstarter.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

=cut


use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use RUNONCE;
use NetPass::LOG qw(_log _cont);

my $myName = "appstarter";

NetPass::LOG::init [ $myName, 'local0' ]; #*STDOUT;

my $otherPid = RUNONCE::alreadyRunning($myName);

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

require NetPass;
require NetPass::Config;
require NetPass::DB;

$SIG{'ALRM'} = \&alarmHandler;


my %opts;
getopts('c:qnDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;

if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize($myName, "/var/run/netpass");
}

print "new NP\n" if $D;

my $np = new NetPass(-config => defined $opts{'c'} ? $opts{'c'} :
		     "/opt/netpass/etc/netpass.conf",
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to create NetPass object" unless defined $np;

print "DB connect\n" if $D;

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


while (1) {
    _log "DEBUG", "wakeup: processing worklist\n" if $D;

    RUNONCE::handleConnection();
    my $ar = $dbh->get();


    if (!defined($ar)) {
	_log "ERROR", "db error ".$dbh->error."\n";
    }

    foreach my $row (@$ar) {
	if( $np->movePort(-switch => $row->[1],
			  -port   => $row->[2],
			  -vlan   => $row->[3]) ) {
	    $dbh->portMoveCompleted($row->[0]);
	} else {
	    my $e = $np->error;
	    _log "ERROR", "failed to move port $row->[1] p$row->[2] to $row->[3] (ID $row->[0]) ERR=$e\n";
	    $dbh->portMoveCompleted($row->[0], 'unmanaged') if ($e =~ /UNMANAGED/);
	}
    }

    _log "DEBUG", "sleeping for 10 seconds.\n" if $D;
    print scalar localtime(time()), " sleeping...\n" if $D;

    select(undef, undef, undef, 10.0);

}



exit 0;



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
