#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/ciconf.pl,v 1.1 2005/04/11 18:17:13 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 ciconfig.pl  "check in config"

=head1 SYNOPSIS

 ciconfig.pl [-c config] [-D] [-u] [-f] [-m 'msg']
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -D             enable debugging
     -u             unlock the config
     -f             force. break an existing lock.
     -m msg         use this log message

=head1 OPTIONS

 See above.

=head1 DESCRIPTION

Import a configuration file into the database. The imported configuration
file becomes the current active config for the NetPass system. If you don't
plan on making more edits, unlock the configuration. Otherwise, the web
interface will give people warnings about the configuration being locked
if they attempt to change it.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: ciconf.pl,v 1.1 2005/04/11 18:17:13 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;
require NetPass::Config;

my %opts;
getopts('c:m:qufDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};

my $npdbh = new NetPass::DB();

die "failed to connect to database ".DBI->errstr unless defined($npdbh);

my $fh = new FileHandle $opts{'c'}, "r";
die qq{cant open $opts{'c'} for reading: $!} unless defined($fh);
my @c = <$fh>;
$fh->close;

print "Read ", ($#c+1), " lines from ", $opts{'c'}, "\n";

my $whoami = `/usr/bin/whoami`;
chomp($whoami);

my @log;

if (exists $opts{'m'}) {
	@log = ( $opts{'m'} ) ;
} else {
	print "Enter a log message (^D to end):\n";
	@log = <STDIN>;
}

my $rv = $npdbh->isConfigLocked();

die "failed to check lock status: $rv" 
  if ( (ref($rv) ne "HASH") && ($rv =~ /db failure/) );

#use Data::Dumper;
#print "rv $rv ref ", ref($rv), "\n", Dumper($rv), "\n";


if (ref ($rv) eq "HASH") {
	my ($user, $rev) = ($rv->{'user'}, $rv->{'rev'});

	# config is locked by someone

	$user = $rv->{'user'};
	$rev  = $rv->{'rev'};

	# if it was locked by us -> putconfig. leave locked.
	# if it was locked by someone else and force -> unlock, lock, putconfig.
	# if it was locked by someone else and no force -> error

	if ( $user eq $whoami ) {
		$rv = $npdbh->putConfig(-config => \@c, -user => $whoami, -log => \@log);
		if ($rv) {
			warn "failed to put new config (unlocking config): $rv";
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
			print "Successfully unlocked config.\n";
			exit 255;
		}
		print "Successfully stored config.\n";
		if (exists $opts{'u'}) {
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
			print "Successfully unlocked config.\n";
		}
	}

	# else, config is locked, but not by us

	elsif ( exists $opts{'f'} ) {
		print "Config is locked by $user. Forcing unlock.\n";
		$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
		die "failed to unlock config: $rv" if $rv;
		$rv = $npdbh->lockConfig(-rev => $rev, -user => $whoami);
		die "failed to lock config: $rv" if $rv;

		$rv = $npdbh->putConfig(-config => \@c, -user => $whoami, -log => \@log);
		if ($rv) {
			warn "failed to put new config (unlocking config): $rv";
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
			print "Successfully unlocked config.\n";
			exit 255;
		}
		print "Successfully stored config.\n";
		if (exists $opts{'u'}) {
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
			print "Successfully unlocked config.\n";
		}
	}

	# else config is locked, not by us, and no force specified.

	else {
		print qq{Error: configuration is currently locked by "$user" (rev $rev)\n};
		exit 255;
	}
} else {
	# else config is not locked. lock it, import it, unlock it (if -u)

	$rv = $npdbh->getConfig(-user => $whoami, -lock => 1);
	die "failed to lock config: $rv" if (ref($rv) ne "HASH");
	my $rev = $rv->{'rev'};

	# if this is an initial import, rev will be undef

	$rev ||= 0;

	$rv = $npdbh->putConfig(-config => \@c, -user => $whoami, -log => \@log);
	if ($rv) {
		warn "failed to put new config (unlocking config): $rv";
		if ($rev > 0) {
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
		}
		print "Successfully unlocked config.\n";
		exit 255;
	}
	print "Successfully stored config.\n";
	if (exists $opts{'u'}) {
		if ($rev > 0) {
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
		}
		print "Successfully unlocked config.\n";
	}
}

exit 0;
