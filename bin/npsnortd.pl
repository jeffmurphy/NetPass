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
use vars qw($remote_ip %opts);

use Getopt::Std;
use Pod::Usage;
use IO::SessionSet;
use Socket;
use FileHandle;
use File::Tail;
use threads;
require NetPass::Snort;
require SOAP::Transport::TCP;
require SOAP::Lite;


my $DEFAULTPORT		= 20011;
my $DEFAULTSNORTLOG	= "/opt/snort/logs/snort.log";
my $DEFAULTSNORTRULES	= "/opt/snort/etc/snort.rules";

getopts('s:S:c:p:r:l:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};
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

# process snort logs from here on in
my $logfile = (exists $opts{'l'}) ? $opts{'l'} : $DEFAULTSNORTLOG;
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

package NetPass::Snort;

use strict;
use Digest::MD5 qw(md5_hex);
use SOAP::Lite;
use Sys::HostIP;
use FileHandle;

my $check_soap_auth = sub {
        my $self         = shift;
        my $their_secret = shift;
        my $rip          = $::remote_ip;
	my %opts	 = %::opts;

	my $my_secret    = md5_hex($rip.$opts{'S'});

	return ($their_secret eq $my_secret) ? 1 : 0;
};

my $snortGetPid = sub {
	my %opts = %::opts;
	my $fh   = new FileHandle;

	if (-e $opts{'p'} && $fh->open($opts{'p'})) {
		my $pid = <$fh>;
		chomp $pid;
		$fh->close;
		return $pid;
	}
	
	return undef;
};

my $snortRunning = sub {
	my $self = shift;

	my $pid = $self->$snortGetPid();
	return undef unless $pid;

        return 1 if (kill(0, $pid) > 0);
        return undef;
};

my $createSoapConnection = sub {
	my %opts = %::opts;

        foreach my $server (split(/\,/, $opts{'s'})) {
		my $proxy = "tcp://$server:20003"; 
		my $soap  = SOAP::Lite->new(
				   	    uri   => 'tcp://netpass/NetPass/API',
                           	   	    proxy => $proxy,
                          	  	   );
		return undef unless defined $soap;

		# check to make sure we have a good connection
		my $rv = eval {$soap->echo()->result};
		return $soap if $rv
        }

	return undef;
};

sub restartSnort {
        my $self         = shift;
        my $key          = shift;
        my %opts         = %::opts;
	my $fh		 = new FileHandle;
	my $md5  	 = md5_hex(hostip.$opts{'S'});

        return undef unless ($self->$check_soap_auth($key));
        return undef unless ($self->$snortRunning());

        my $pid = $self->$snortGetPid();
        return undef unless $pid;

	my $soap = $self->$createSoapConnection();
	return undef unless $soap;

        # rewrite snort rules file here

	my $aref = eval {$soap->getSnortRules($md5,"all")->result};
	return undef unless defined($aref) && (ref($aref) eq 'ARRAY');

	# add checking for rules file and make backup
	

        return 1 if (kill(1, $pid) > 0);
	return undef;
}

sub snortRunning {
        my $self = shift;
        my $key  = shift;

        return $self->$snortRunning() if ($self->$check_soap_auth($key));
        return undef;
}


1;
