#!/opt/perl-5.8.6/bin/perl -w

use strict;
use vars qw($np $remote_ip);

use Getopt::Std;
use Pod::Usage;
use SOAP::Transport::TCP;
use SOAP::Lite;
use IO::SessionSet;
use Socket;

use lib '/opt/netpass/lib';
use RUNONCE;
use NetPass::LOG qw(_log _cont);
NetPass::LOG::init [ 'npapid', 'local0' ]; #*STDOUT;
use NetPass;
use NetPass::API;

my $otherPid = RUNONCE::alreadyRunning('npapi');

if(defined($otherPid) && $otherPid) {
    _log "ERROR", "i'm already running. pid=$otherPid\n";
    die "ERR: another copy of this script is already running pid=$otherPid";
}

$SIG{'ALRM'} = \&alarmHandler;

my %opts;
getopts('c:U:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;
if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize("npapid", "/var/run/netpass");
}

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

$np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
	          -dbuser => $dbuser, -dbpass => $dbpass,
		  -debug  => exists $opts{'D'} ? 1 : 0,
		  -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");


_log("DEBUG", "starting SOAP server");

my $daemon = SOAP::Transport::TCP::Server->new(
						LocalPort       => $np->cfg->npapiPort(),
						Listen          => 5,
						Reuse           => 1,
				              )->dispatch_to('NetPass::API');

if (!$daemon) {
   _log("ERROR", "Unable to start SOAP Server");	
   die("Unable to start SOAP Server"); 
}

# handler borrowed from SOAP::Transport::TCP

my $sock        = $daemon->{_socket};
my $session_set = IO::SessionSet->new($sock);
my %data;

while (1) {
   my @ready = $session_set->wait($sock->timeout);
   for my $session (@ready) {
      my $s = $session->handle->peername;
      $remote_ip = inet_ntoa((sockaddr_in($s))[1]); 

      _log("DEBUG", "processing soap API call from $remote_ip");
 
      # we may be able to evaluate md5 hash here
      # but we will need to do xml parsing.

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

1;
