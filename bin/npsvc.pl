#!/opt/perl/bin/perl -w

=head1 NAME

 npsvc.pl

=head1 SYNOPSIS

 npsvc.pl <-c configfile> <-w time> <-m mailserver>
     -c configfile	  npsvc.pl config file
     -w	time		  period of time to wait before starting to watch procs
     -m mailserver	  smtp mail server
     -h                   this message


=head1 DESCRIPTION

A script to watch processes listed in the npsvc config file

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

=cut

use strict;
use Getopt::Std;
use Pod::Usage;
use FileHandle;
use Net::SMTP;
use Data::Dumper;
use POSIX;

use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use RUNONCE;

$RUNONCE::SANITY = 0;

my $proctowatch     = {};
my $DEFAULTCONFIG   = "/opt/netpass/etc/npsvc.conf";
my $WAITPERIOD      = 300;
my $EMAILTIMEOUT    = 300;

sub REAPER {
	my $child;
	while (($child = waitpid(-1,WNOHANG)) > 0) {
	}
	$SIG{'CHLD'} = \&REAPER;
}

$SIG{'HUP'}  = \&handler;
$SIG{'CHLD'} = \&REAPER; # just incase they fail to disassociate

my %opts;
getopts('s:c:m:w:hD', \%opts);
pod2usage(2) if exists $opts{'h'};

my $config   = (exists $opts{'c'}) ? $opts{'c'} : $DEFAULTCONFIG;
my $waittime = (exists $opts{'w'}) ? $opts{'w'} : $WAITPERIOD; 
my $D        = (exists $opts{'D'}) ? 1          : 0;
my $ST       = (exists $opts{'s'}) ? $opts{'s'} : 30;

if (exists $opts{'D'}) {
	NetPass::LOG::init *STDOUT;
} else {
	NetPass::LOG::init [ 'npsvc', 'local0' ];
}

die "File $config does not exist!" unless -e $config; 

my $mailserver = (exists $opts{'m'}) ? $opts{'m'} : ""; 

$proctowatch = processConfFile($config);
sleep($waittime);

print "Config is:\n", Dumper($proctowatch), "\n";

while (1) {
	print scalar(localtime), " wakeup\n" if $D;

	if (! -e "/var/lock/subsys/netpass") {
		print scalar(localtime), " /var/lock/subsys/netpass doesnt exist. go to sleep.\n"
		  if $D;
		sleep ($ST);
		next;
	}

	foreach my $svc (keys %$proctowatch) {
		print scalar(localtime), " doing $svc\n" if $D;
		my $pid = RUNONCE::alreadyRunning($svc);
		next if ($pid > 0);
		RUNONCE::close;
		
		my $action = $proctowatch->{$svc}{'action'};

		if ($mailserver ne "" &&
		    time() > ($proctowatch->{$svc}{'lastemailed'} + $EMAILTIMEOUT)) {
			print scalar(localtime), " sending email for $svc\n";
			Email("npsvc",
			      $proctowatch->{$svc}{'email'},
			      "$svc down $action",
			      "Service $svc is down. Performing action: $action",
			      $mailserver);
			      $proctowatch->{$svc}{'lastemailed'} = time();
		}
		if ($action eq 'restart') {
			print scalar(localtime), " restarting $svc\n";
			runAs($proctowatch->{$svc}{'cmd'});
		}
	}
	print scalar(localtime), " sleeping for $ST seconds\n" if $D;
	sleep ($ST);
}

exit 0;

sub Email {
        my($from, $to, $subject, $mesg, $mailserver) = @_;
        my $smtp = Net::SMTP->new($mailserver);

        if (!$smtp) {
                _log("WARNING", "There was a problem creating the SMTP object.\n");
        } else {
		use Sys::Hostname;
		my $shn = (split(/\./, hostname))[0];
		$shn ||= hostname;
		$smtp->mail($from);
		$smtp->to($to);
		$smtp->data();
		$smtp->datasend("Subject: $shn: $subject");
		$smtp->datasend("\n\n\n");
		$smtp->datasend($shn.":\n\n".$mesg);
		$smtp->quit;
	}

        return (1);
}

sub handler {
	$proctowatch = processConfFile($config);
	return 1;
}

sub processConfFile {	
	my $file = shift;
	my $fh   = new FileHandle();
	my %pw;

	$fh->open($file) || die "Unable to open $file";
	while (my $line = $fh->getline) {
		chomp($line);
		print "config: <$line>\n" if $D;
        	next if ($line =~ /^\s*\#/);
        	my($port, $email, $action, $cmd) = split(/\s+/, $line, 4);
		print "config(pre-regexp): <$port> <$email> <$action> <$cmd>\n" if $D;
		if ($email !~ /^[^@]+\@\w*\.*\w*\.*\w+\.\w+$/) {
			print "config(email) <$email> didnt parse\n";
		}
		if (! -e (split(/\s+/, $cmd))[0]) {
			print "config(cmd) <$cmd> not executable\n";
		}
        	next	 if ($cmd eq '' || 
			     $email !~ /^[^@]+\@\w*\.*\w*\.*\w+\.\w+$/ || 
			     $port eq '' ||
			     $action !~ /^(restart|norestart)$/ ||
			     !-e (split(/\s+/, $cmd))[0]);
		print "config(post-regexp): <$port> <$email> <$action> <$cmd>\n" if $D;

        	$pw{$port}{'cmd'}    = $cmd;
        	$pw{$port}{'email'}  = $email;
        	$pw{$port}{'action'} = $action;
        	$pw{$port}{'lastemailed'} = 0;
	}
	$fh->close();
	return \%pw;
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

	_log("DEBUG", qq{forking to exec as $as cmd "$cmd"\n}) if $D;
	my $child = fork;
	return if (defined($child) && ($child > 0)); # parent

	setsid or _log("WARNING", "$$ child failed to setsid $!\n");

	_log("DEBUG", "$$ inchild change to uid=$uid gid=$gid\n");

	my $rv = setgid($gid);

	unless ($rv) {
		_log("ERROR", "$$ child failed to setgid($gid) rv=$rv err=$!\n");
		exit 0;
	}
	$rv = setuid($uid);
	unless ($rv) {
		_log("ERROR", "$$ child failed to setuid($uid) rv=$rv err=$!\n");
		exit 0;
	}
	{
		_log("DEBUG", qq{$$ in child. calling exec\n}) if $D;
		open STDIN, '/dev/null';
		open STDOUT, '>/dev/null';
		exec($cmd);
	}
	_log("ERROR", "child $$ failed to exec($cmd) $!\n");
	exit 0;
}

