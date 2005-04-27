#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/portmover.pl,v 1.5 2005/04/27 03:54:06 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

portmover.pl - long running daemon that watches the portMoves database
table and processes pending transactions.

=head1 SYNOPSIS

 moveport.pl [-c cstr] [-U user/pass] [-n] [-q] [-D] 
     -c cstr        db connect string
     -U user/pass   db user[/pass]
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging

=head1 OPTIONS

=over 8

=item B<-c cstr>

DB to connect to.

=item B<-U user/pass>

Credentials to use when connecting to DB.

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

This script waits for new transactions to appear in the movePorts table. It then
processes the transactions. We do this primarily to avoid a deadlock that occurs
when a web script moves a port before the webserver has closed the connection.

Sending an ALRM signal to this script will cause it to immediately read the table. Otherwise
it reads it once every 10 seconds.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: portmover.pl,v 1.5 2005/04/27 03:54:06 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use RUNONCE;
use NetPass::LOG qw(_log _cont);

NetPass::LOG::init [ 'portmover', 'local0' ]; #*STDOUT;

my $otherPid = RUNONCE::alreadyRunning('portmover');

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

require NetPass;

$SIG{'ALRM'} = \&alarmHandler;

my %opts;
getopts('c:qnDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;

if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize("portmover", "/var/run/netpass");
}

print "new NP\n" if $D;

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

while (1) {
    _log "DEBUG", "wakeup: processing worklist\n" if $D;

    RUNONCE::handleConnection();
    my $ar      = $np->db->getPortMoveList();
    my $didWork = 0;


    if (!defined($ar)) {
	_log "ERROR", "db error ".$np->db->error."\n";
	next;
    }

    foreach my $row (@$ar) {
	    $didWork = 1;
	    if( $np->movePort(-switch => $row->[2],
			      -port   => $row->[3],
			      -vlan   => $row->[4]) ) {
		    $np->db->portMoveCompleted($row->[1]);
	    } else {
		    my $e = $np->error;
		    _log "ERROR", "failed to move port $row->[2] p$row->[3] to $row->[4] (ID $row->[0] $row->[1]) ERR=$e\n";
		    $np->db->portMoveCompleted($row->[1], 'unmanaged') if ($e =~ /UNMANAGED/);
	    }
    }

    # if we've been busy, immediately re-check the queue. otherwise sleep
    # for a bit.

    if ($didWork == 0) {
	    print scalar localtime(time()), "we didnt do anything. sleep for 10secs.\n" if $D;
	    select(undef, undef, undef, 10.0);
    } else {
	    print scalar localtime(time()), "we've been busy. no time for sleep.\n" if $D;
    }

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
