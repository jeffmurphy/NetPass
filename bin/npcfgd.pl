#!/usr/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/Attic/npcfgd.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

npcfgd.pl - long running daemon which exports the
NetPass::Config::Network object to other netpass daemons 
via the SOAP API.

=head1 SYNOPSIS

 npcfgd.pl [-c config] [-q] [-D] 
     -c configFile  [default /opt/netpass/etc/netpass.conf]
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

=item B<-D> 

Enable debugging output. This flag causes this script to run in the foreground.
Otherwise, this script will detach and run in the background.

=back

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: npcfgd.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

=cut

use strict;
use vars qw($cfg $remote_ip);

use Getopt::Std;
use Pod::Usage;
use SOAP::Transport::TCP;
use SOAP::Lite;
use IO::SessionSet;
use Socket;

use lib '/opt/netpass/lib';
use RUNONCE;
use NetPass::LOG qw(_log _cont);
NetPass::LOG::init [ 'npcfgd', 'local0' ]; #*STDOUT;
use NetPass;
use NetPass::Config;
use NetPass::Config::Network;

my $otherPid = RUNONCE::alreadyRunning('npcfgd');

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

$SIG{'ALRM'} = \&alarmHandler;

my %opts;
getopts('c:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;
if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize("npcfgd", "/var/run/netpass");
}

$cfg = new NetPass::Config(defined $opts{'c'} ? $opts{'c'} :
			   "/opt/netpass/etc/netpass.conf");

die ("Unable to access netpass config object") if (!$cfg);

my $daemon = SOAP::Transport::TCP::Server->new(
						LocalPort       => $cfg->npcfgdPort(),
						Listen          => 5,
						Reuse           => 1,
				              )->dispatch_to('NetPass::Config::Network');
die("Unable to create SOAP Server") if (!$daemon); 

# handler borrowed from SOAP::Transport::TCP

my $sock        = $daemon->{_socket};
my $session_set = IO::SessionSet->new($sock);
my %data;

while (1) {
   my @ready = $session_set->wait($sock->timeout);
   for my $session (@ready) {
      my $s = $session->handle->peername;
      $remote_ip = inet_ntoa((sockaddr_in($s))[1]); 
      my $data;
      if (my $rc = $session->read($data, 4096)) {
         $data{$session} .= $data if $rc > 0;
      } else {
         $session->write(
         $daemon->SOAP::Server::handle(delete $data{$session}));
         $session->close;
      }  
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
