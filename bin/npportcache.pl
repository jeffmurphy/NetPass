#!/usr/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/npportcache.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $
#


=head1 NAME

npportcache.pl - long running daemon that listens for requests for SNMP information
from netpass code and performs the queries for the code. 

=head1 SYNOPSIS

 npportcache.pl [-c config] [-n] [-q] [-D] [-p port]
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -p #           port to listen on
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

=item B<-p #>

Specify the port number to listen on. If not specified, we'll use the port
defined as "portcacher" in C</etc/services>

=back

=head1 DESCRIPTION

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: npportcache.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

=cut


use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;
use IO::Socket;

use Set::Scalar;
use Data::Dumper;

use RUNONCE;
use NetPass::LOG qw(_log _cont);


NetPass::LOG::init *STDOUT;
#NetPass::LOG::init [ 'npportcache', 'local0' ]; #*STDOUT;

my $otherPid = RUNONCE::alreadyRunning('npportcache');

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

require NetPass;
require NetPass::Config;
require NetPass::DB;

$SIG{'ALRM'} = \&alarmHandler;

my %opts;
getopts('c:p:qnDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;

if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize("npportcache", "/var/run/netpass");
}

print "new NP\n" if $D;

my $np = new NetPass(-config => defined $opts{'c'} ? $opts{'c'} :
                     "/opt/netpass/etc/netpass.conf",
                     -debug => exists $opts{'D'} ? 1 : 0,
                     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to create NetPass object" unless defined $np;

# forever:
#     check for new cnx, add to cnx list
#     check for data on existing cnxs, add to work list
#     process worklist
# done
#
# processworklist:
# foreach item in worklist
#     if macport(sw,mac) then
#         if cache{sw} exists && cache{sw}->{mac} exists && data is not stale then
#             return data, delete item from worklist
#         else
#             skip this item for now
#         endif
#     endif
# endeach
# remaining items in worklist are stale or unknown
# 
# group them by switch and query type (macport or topo)
# if macport then
#    fetch mac table for each switch
#    update cache
# endif
# if topo then
#    fetch topo from each switch
#    update cache
# endif
# re-process worklist
# worklist should now be empty


_log("DEBUG", "getprotobyname..\n") if exists $opts{'D'};

my $proto = getprotobyname('tcp');
die "getprotobyname failed: $!" unless defined($proto);

_log("DEBUG", "determine port ..\n") if exists $opts{'D'};

my $port = $opts{'p'} || getservbyname('portcacher', 'tcp');
die "not sure what port to bind to $!" 
  unless (defined($port) && ($port > 0) && ($port < 65536));

_log("DEBUG", "new IO::Socket::INET port=$port..\n") if exists $opts{'D'};

# XXX netpass.conf

my $SH = IO::Socket::INET->new(Listen    => 256,
			       Proto     => 'tcp',
			       LocalAddr => '127.0.0.1',
			       LocalPort => $port,
			       Reuse     => 1,
			       Timeout   => 1);

if (!defined($SH)) {
    die "couldnt create new IO::Socket;:INET $!";
}

#$SH->blocking(0);
#$SH->timeout(1);

my $rin; my $win; 
$rin = $win = '';
my @fdList;
my $Cache;
$Cache->{'128.205.15.241'} = {};
$Cache->{'128.205.15.241'}->{'000000000002'} = 24;
$Cache->{'128.205.15.241'}->{'port-24'} = [ '000000000002', '000000000001' ];
$Cache->{'128.205.15.241'}->{'age-24'} = time()-300;

while (1) {

    # accept any pending new connections. accept will
    # block for Timeout seconds (see constructor above).

    $rin = checkForNewConnections($SH, $rin, \@fdList);

    # figure out if any of our open connections has
    # data on it we should read. we'll wait 1 second
    # to see if any data shows up. then we need to 
    # go see if there are new connections to accept.

    my $rout = $rin;
    my $numFds = select($rout, undef, undef, 1);
    if ($numFds >= 0) {
	_log("DEBUG", "$numFds clients want to talk to us!\n") if exists $opts{'D'};

	# figure out which FDs have data waiting and process
	# that data.

	for (my $i = 0 ; $i < 32 ; $i++) {
	    if (vec($rout, $i, 1) == 1) {
		handleClientInput($i, \@fdList);
	    }
	}
    }

    print scalar(localtime()), " nothing to do. continue polling.\n";
}


exit 0;

sub handleClientInput {
    my $fdn = shift;
    my $fdl = shift;

    my $buf;

    my $fd = $fdl->[$fdn];

    _log ("DEBUG", "handleClientInput(".fileno($fd).")\n") if exists $opts{'D'};

    
    my $got = sysread($fd, $buf, 256);
    if($got == 0) {
	# eof. close the connection
	_log ("DEBUG", fileno($fd)." closed the connection.\n") if exists $opts{'D'};
	vec($rin, fileno($fd), 1) = 0;
	$fd->close();
	$fdl->[$fdn] = undef;
    } else {
	chomp($buf); chop($buf);
	_log ("DEBUG", fileno($fd)." sent us $got bytes: \"$buf\"\n") if exists $opts{'D'};
	my ($mac, $ip) = split(' ', $buf);
	if (!defined($mac) || !defined($ip)) {
	    _log ("ERROR", fileno($fd)." sent us bad data. no mac or ip given: \"$buf\"\n");
	} else {

	    $mac = padMac($mac);

	    # figure out which network we are on
	    # search all switches for a cache entry that matches us
	    # if that entry is young enough, return it
	    # else 
	    #   search the network
	    #   update the cache
	    # endif

	    _log("DEBUG", "mac=$mac ip=$ip\n") if exists $opts{'D'};

	    my $nw = $np->cfg->getMatchingNetwork($ip);
	    if (!defined($nw)) {
		_log ("ERROR", "no network matches $ip\n");
		syswrite($fd, "nonetwork\n");
	    } else {
		_log ("DEBUG", "network $ip is $nw\n") if exists $opts{'D'};
		foreach my $switch (@{$np->cfg->getSwitches($nw)}) {
		    my $port = $Cache->{$switch}->{$mac};
		    if (defined($port)) {
			my $managedPortList = $np->cfg->configuredPorts($switch);
			if (!defined($managedPortList)) {
			    _log("WARNING", "no managed ports on $switch\n");
			} else {
			    foreach my $p (@$managedPortList) {
				if ($p == $port) {
				    my $buffer = "$switch $port ";
				    $buffer .= join(',', 
						    @{$Cache->{$switch}->{'port-'.$p}});
				    $buffer .= "\n";
				    syswrite($fd, $buffer);
				    last;
				}
			    }
			}
		    }
		}
	    }
	}
    }
}

sub padMac {
        my $m = shift;
        return $m unless defined($m);
        $m = "0" x (12-length($m)) . $m;
        $m =~ tr [A-Z] [a-z];
        return $m;
}

sub checkForNewConnections {
    my $sh  = shift;
    my $rin = shift;
    my $fdl = shift;

    _log("DEBUG", "calling accept..\n") if exists $opts{'D'};
    my $cnx = $sh->accept();

    # remember the descriptor this connection
    # is assigned too

    if (defined($cnx)) {
	_log("DEBUG", "accepting new connection on fd ".fileno($cnx)."\n") if exists $opts{'D'};
	vec($rin, fileno($cnx), 1) = 1;
	$fdl->[fileno($cnx)] = $cnx;
    } else {
	_log("DEBUG", "no new connections to accept..\n") if exists $opts{'D'};
    }
    return $rin;
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
