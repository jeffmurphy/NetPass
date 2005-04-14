#!/usr/bin/perl -w

=head1 NAME

 npsnortd.pl

=head1 SYNOPSIS

 npsnortd.pl
     -s srvr1,srvr2...    the server npapid is running on
     -S secret            the secret key
     -l logfile		  the snort log file
     -r rulesfile	  the snort rules file
     -P port		  the port npsnortd will run on	  	
     -p pidfile		  snort pid file
     -h                   this message


=head1 DESCRIPTION

This is the snort API daemon
 
=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

=cut

#
# This perl script needs the following modules
#	SOAP::Lite
#	SOAP::Transport::TCP
#	Sys::HostIP
#

use strict;

use Getopt::Std;
use Pod::Usage;
use IO::SessionSet;
use Socket;
use FileHandle;
use File::Tail;
use Sys::HostIP;
use Digest::MD5 qw(md5_hex);
use threads;
use SOAP::Transport::TCP;
use SOAP::Lite;

use lib '/u1/students/mtbell/NetPass/lib';
use NetPass::Snort;

use vars qw($remote_ip %opts);

my $DEFAULTPORT		= 20008;
my $DEFAULTSNORTLOG	= "/opt/snort/logs/snort.log";

getopts('s:S:p:r:l:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'}  || exists $opts{'?'};
pod2usage(2) if !exists $opts{'s'} || !exists $opts{'S'};

if ($opts{'s'} !~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\,*)+$/) {
	pod2usage(2);
}

my $D = 0;
if (exists $opts{'D'}) {
	$D = 1;
} else {
	daemonize("npsoapd", "/var/run");
}

my $tid = threads->create(\&soapServer, \%opts);
die "Unable to spawn soap server thread." unless $tid;
$tid->detach;

# process snort logs from here on in
my $logfile = (exists $opts{'l'}) ? $opts{'l'} : $DEFAULTSNORTLOG;
die "Unable to open $logfile" unless -e $logfile;

my $fh = new File::Tail (
				name        => $logfile,
                         	interval    => 3,
                         	maxinterval => 5
			);

die "Cannot open file $logfile" unless defined ($fh);

my $secret = md5_hex(hostip.$opts{'S'});

while (1) {
	my %data;

        while ($fh->predict == 0) {
                my $l = $fh->read;	
		chomp $l;
		my($sid, $ip) = split(/\,/, $l);
		next unless defined($ip) && defined($sid);
		$data{$ip}{$sid} = $sid;
        }

	next if (keys(%data) == 0);

	my $soap = createSoapConnection();
	if (!$soap) {
		warn "Unable to Connect to npapid server";
		next;
	}

	foreach my $ip (keys %data) {
		my $res = eval {$soap->processIP($secret, $ip, keys(%{$data{$ip}}))->result};
		if (!$res) {
			warn "Wasn't Able to process $ip";
			next;
		}
		print "processing $ip sids = ".join(',', keys(%{$data{$ip}}))." resulted in $res\n";
	}
}

exit 0;

sub createSoapConnection {
	foreach my $server (split(/\,/, $opts{'s'})) {
		my $proxy = "tcp://$server:20003";
		my $soap  = SOAP::Lite->new(
					    uri   => 'tcp://netpass/NetPass/API',
					    proxy => $proxy,
					   );

		return undef unless defined $soap;
		my $rv = eval {$soap->echo()->result};
		return $soap if $rv;
	}

	return undef;
}

sub soapServer {
	my $opts = shift;
	my $port = (exists $opts->{'P'}) ? $opts->{'P'} : $DEFAULTPORT;

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

sub daemonize {
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
