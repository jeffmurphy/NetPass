#!/opt/perl/bin/perl -w

use strict;
use vars qw($cfg $remote_ip);

use Getopt::Std;
use Pod::Usage;
use IO::SessionSet;
use Socket;
use Config::General;
use FileHandle;
use File::Tail;
use threads;
require SOAP::Transport::TCP;
require SOAP::Lite;

my %opts;
getopts('c:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $D = 0;
if (exists $opts{'D'}) {
    $D = 1;
} else {
    daemonize("npsoapd", "/var/run");
}

$cfg = new Config::General(-ConfigFile        => $opts{'c'} ? $opts{'c'} :
	           				 "/opt/netpass/etc/npsnortd.conf" ,
                           -AutoTrue          => 1,
                           -IncludeRelative   => 1,
                           -UseApacheInclude  => 1,
                           -ExtendedAccess    => 1,
                           -StrictObjects     => 0
                          );
die "Unable to read config file ".$opts{'c'} unless $cfg;

my $tid = threads->create(\&soapServer, $cfg);
die "Unable to spawn soap server thread." unless $tid;

# process snort logs from here on in
my $logfile = $cfg->obj('npsnortd')->value('snortlog');
die "Unable to open $logfile" unless -e $logfile;

my $fh = new File::Tail (
				name        => $logfile,
                         	interval    => 3,
                         	maxinterval => 5
			);

die "Cannot open file $logfile" unless defined ($fh);

while (1) {
	my @lines = ();

        while ($fh->predict == 0) {
                push @lines, $fh->read;
        }

	print @lines;
}

exit 0;

sub soapServer () {
	my $port = $cfg->obj('npsnortd')->value('port');
	die "No Port Specified for SOAP server to run on." unless $port;

	my $daemon = SOAP::Transport::TCP::Server->new(
							LocalPort       => $port,
							Listen          => 5,
							Reuse           => 1,
				              	      )->dispatch_to('NetPass::Snort');
	die("Unable to create SOAP Server") if (!$daemon); 

	my $sock        = $daemon->{_socket};
	my $session_set = IO::SessionSet->new($sock);
	my %data;

	while (1) {
		my @ready = $session_set->wait($sock->timeout);
		for my $session (@ready) {
			my $data;
			my $s = $session->handle->peername;
			$remote_ip = inet_ntoa((sockaddr_in($s))[1]); 
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

sub daemonize () {
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

package NetPass::Snort;

use strict;
use Digest::MD5 qw(md5_hex);

sub check_soap_auth {
        my $self         = shift;
        my $their_key    = shift;
        my $rip          = $::remote_ip;
        my $cfg          = $::cfg;

        my $secret       = $cfg->obj('npsnortd')->value('secret');
        my $my_key       = md5_hex($rip.$secret);

        return ($their_key eq $my_key) ? 1 : 0;
}

sub snortRunning () {
	my $self = shift;
	my $key  = shift;
        my $cfg  = $::cfg;
	my $fh   = new FileHandle;

	return -1 if (!$self->check_soap_auth($key));
	my $pfile = $cfg->obj('npsnortd')->value('snortpid');

	if (-e $pfile && $fh->open($pfile)) {
		my $pid = <$fh>;
		chomp $pid;
		$fh->close;
		my $r = kill(0, $pid);
		return 1 if $r;
	}

	return 0;
}

sub restartSnort () {
	my $self = shift;
	my $key  = shift;
        my $cfg  = $::cfg;
	my $fh   = new FileHandle;

	return -1 if (!$self->check_soap_auth($key));
	my $pfile = $cfg->obj('npsnortd')->value('snortpid');

        if (-e $pfile && $fh->open($pfile)) {
                my $pid = <$fh>;
		chomp $pid;
                $fh->close;
                my $r = kill(1, $pid);
                return 1 if $r;
        }

	return 0;
}

1;
