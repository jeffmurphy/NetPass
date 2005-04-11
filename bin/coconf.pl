#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/coconf.pl,v 1.1 2005/04/11 18:17:13 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 coconfig.pl 

=head1 SYNOPSIS

 coconfig.pl [-c config] [-D] [-l] [-r rev] [-f] [-o file]
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -D             enable debugging
     -l             lock the configuration
     -r rev         export a specific revision
     -f             force the lock if someone else holds it
     -o file        write config to file (default STDOUT)

=head1 OPTIONS

 See above.

=head1 DESCRIPTION

Export a configuration file from the database. Optionally lock it.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: coconf.pl,v 1.1 2005/04/11 18:17:13 jeffmurphy Exp $

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
getopts('o:c:qflr:Dh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};

my $npdbh = new NetPass::DB();

die "failed to connect to database ".DBI->errstr unless defined($npdbh);

my $whoami = `/usr/bin/whoami`;
chomp($whoami);

my $rv;
my $rev = exists $opts{'r'} ? $opts{'r'} : "";

if (exists $opts{'l'}) {
	if ($rev ne "") {
		if (exists $opts{'f'}) {
			$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to force unlock config: $rv" if $rv;
		}
		$rv = $npdbh->lockConfig(-rev  => $rev,
					 -user => $whoami);
		die "failed to lock config: $rv" if $rv;
	} else {
		my $hv = $npdbh->getConfig();
		if ( (ref($hv) eq "HASH") && ($hv->{'rev'} > 0) ) {
			$rev = $hv->{'rev'};
			if (exists $opts{'f'}) {
				$rv = $npdbh->unlockConfig(-rev => $rev, -user => $whoami);
				die "failed to force unlock config: $rv" if $rv;
			}

			$rv = $npdbh->lockConfig(-rev  => $rev,
						 -user => $whoami);
			die "failed to lock config: $rv" if $rv;
		}
	}
	print "# Configuration revision $rev locked for editing.\n";
}


$rv = $npdbh->getConfig(-rev => $rev);

die "failed to fetch config: $rv" if (ref($rv) ne "HASH");

#use Data::Dumper; print Dumper($rv);

if (exists $opts{'o'}) {
	my $fh = new FileHandle $opts{'o'}, "w";
	die qq{fail to open $opts{'o'} for writing: $!} unless defined $fh;
	printConfig($fh, $rv);
	$fh->close;
} else {
	printConfig(*STDOUT, $rv);
}

exit 0;

sub printConfig {
	my $fh = shift;
	my $hv = shift;
	print $fh "# revision ".$hv->{'rev'}."\n";
	print $fh "# created ".scalar(localtime($hv->{'timestamp'}))."\n";
	print $fh "# by: ".$hv->{'user'}."\n";
	print $fh "# log:\n# ".join("\n#", @{$hv->{'log'}})."\n";
	print $fh join("\n", @{$rv->{'config'}}), "\n";
}