#!/usr/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/Attic/npstatd.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

npstatd.pl - long running daemon which which exports stats information 
via the SOAP API

=head1 SYNOPSIS

 npstatd.pl [-c config] [-q] [-D] [-s secret] [-d ipaddress:port]
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -q             be quiet. exit status only.
     -D             enable debugging
     -s secret	    secret used to authenticate to npcfgd server
     -d ip:port	    ip address and port of npcfgd server   	   

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

=item B<-s>

Secret key used in authentication with the npcfgd server. B<-s> is used in
conjunction with B<-d>.

=item B<-d ipaddress:port>

The ipaddress and port of the npcfgd server to connect to. B<-d> is used in
conjunction with B<-s> for authentication purposes.

=back

=head1 SEE ALSO

C<netpass.conf> C<npcfgd>

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: npstatd.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

=cut


use strict;
use Getopt::Std;
use Pod::Usage;
use Digest::MD5 qw(md5_hex);
use Socket;
require SOAP::Lite;
require SOAP::Transport::TCP;

use lib '/opt/netpass/lib';
use RUNONCE;
use NetPass::LOG qw(_log _cont);
use NetPass;
use NetPass::Config;
use NetPass::Stats;
use NetPass::Stats::Network;
NetPass::LOG::init [ 'npstatd', 'local0' ]; #*STDOUT;

use vars qw($cfg $remote_ip);

my $otherPid = RUNONCE::alreadyRunning('npstatd');

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

$SIG{'ALRM'} = \&alarmHandler;

my %opts;
getopts('c:s:d:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};
pod2usage(2) if !exists $opts{'c'} && (!exists $opts{'d'} || !exists $opts{'s'});

my $D = 0;

if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize("npstatd", "/var/run/netpass");
}

if ($opts{'c'}) {
   die "Unable to open ".$opts{'c'} if (!-e $opts{'c'});
   $cfg = new NetPass::Config($opts{'c'});
} elsif ($opts{'s'} && $opts{'d'}) {
   my $ip;
   my $port;

   if ($opts{'d'} =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)$/) {
      $ip   = $1;
      $port = $2;
   } else { pod2usage(2); }

   import SOAP::Lite +autodispatch =>
                     uri     => 'tcp://netpass',
               	     proxy   => "tcp://$ip:$port",
#               	     trace   => $opts{'D'} ? 'debug' : '',
               	     ;
   $cfg = new NetPass::Config::Network(formatSecret($ip, $opts{'s'})) ||
	  die ("Unable to establish a connection to the npcfgd server.");
}

print "port = ".$cfg->npstatdPort()."\n\n\n\n\n\n\n";

my $daemon = SOAP::Transport::TCP::Server->new(
                                                LocalPort       => $cfg->npstatdPort(),
                                                Listen          => 5,
                                                Reuse           => 1,
                                              )->dispatch_to('NetPass::Stats::Network');
die("Unable to create SOAP Server") if (!$daemon);

handler($daemon);

exit 0;

sub handler {
   my $daemon = shift;

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
}

sub formatSecret {
    my $ip     = shift;
    my $secret = shift;

    return md5_hex($ip.$secret);
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
