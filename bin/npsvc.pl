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

use lib qw(/opt/netpass/lib);
use RUNONCE;

my $proctowatch     = {};
my $DEFAULTCONFIG   = "/opt/netpass/etc/npsvc.conf";
my $WAITPERIOD      = 300;
my $EMAILTIMEOUT    = 300;

$SIG{'HUP'} = \&handler;

my %opts;
getopts('c:m:w:h', \%opts);
pod2usage(2) if exists $opts{'h'};

my $config   = (exists $opts{'c'}) ? $opts{'c'} : $DEFAULTCONFIG;
my $waittime = (exists $opts{'w'}) ? $opts{'w'} : $WAITPERIOD; 
die "File $config does not exist!" unless -e $config; 

my $mailserver = (exists $opts{'m'}) ? $opts{'m'} : ""; 

$proctowatch = processConfFile($config);
sleep($waittime);

while (1) {
	foreach my $svc (keys %$proctowatch) {
		my $pid = RUNONCE::alreadyRunning($svc);
		next if ($pid > 0);
		RUNONCE::close;
		
		my $action = $proctowatch->{$svc}{'action'};
		if ($mailserver ne "" &&
		    time() > ($proctowatch->{$svc}{'lastemailed'} + $EMAILTIMEOUT)) {
			Email("npsvc",
			      $proctowatch->{$svc}{'email'},
			      "$svc down $action",
			      "$svc down $action",
			      $mailserver);
			      $proctowatch->{$svc}{'lastemailed'} = time();
		}
		system($proctowatch->{$svc}{'cmd'})
			if ($action eq 'restart');
	}
	sleep (30);
}

exit 0;

sub Email {
        my($from, $to, $subject, $mesg, $mailserver) = @_;
        my $smtp = Net::SMTP->new($mailserver);

        if (!$smtp) {
                warn("There was a problem sending email...");
        }

        $smtp->mail($from);
        $smtp->to($to);
        $smtp->data();
        $smtp->datasend("Subject: $subject");
        $smtp->datasend("\n\n\n");
        $smtp->datasend($mesg);
        $smtp->quit;

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
        	next if ($line =~ /^\s*\#/);
        	my($port, $email, $action, $cmd) = split(/\s+/, $line, 4);
		chomp $cmd;
        	next	 if ($cmd eq '' || 
			     $email !~ /^\w+\@\w*\.*\w*\.*\w+\.\w+$/ || 
			     $port eq '' ||
			     $action !~ /^(restart|norestart)$/ ||
			     !-e $cmd);
        	$pw{$port}{'cmd'}    = $cmd;
        	$pw{$port}{'email'}  = $email;
        	$pw{$port}{'action'} = $action;
        	$pw{$port}{'lastemailed'} = 0;
	}
	$fh->close();
	return \%pw;
}
