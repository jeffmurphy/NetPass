#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/coconf.pl,v 1.4 2005/04/13 20:57:43 jeffmurphy Exp $

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
     -u             unlock the configuration
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

$Id: coconf.pl,v 1.4 2005/04/13 20:57:43 jeffmurphy Exp $

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
getopts('o:c:U:qfulr:Dh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};


my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr  => exists $opts{'c'} ? $opts{'c'} : undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

die "-l and -u are mutually exclusive.\n" if (exists $opts{'l'} && 
					      exists $opts{'u'});

my $whoami = `/usr/bin/whoami`;
chomp($whoami);

my $rv;
my $rev = exists $opts{'r'} ? $opts{'r'} : 0;

if (exists $opts{'l'}) {
	if ($rev != 0) {
		if (exists $opts{'f'}) {
			$rv = $np->db->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to force unlock config: $rv" if $rv;
		}
		$rv = $np->db->lockConfig(-rev  => $rev,
					  -user => $whoami);
		die "failed to lock config: $rv" if $rv;
	} else {
		my $hv = $np->db->getConfig();
		if ( (ref($hv) eq "HASH") && ($hv->{'rev'} > 0) ) {
			$rev = $hv->{'rev'};
			if (exists $opts{'f'}) {
				$rv = $np->db->unlockConfig(-rev => $rev, -user => $whoami);
				die "failed to force unlock config: $rv" if $rv;
			}

			$rv = $np->db->lockConfig(-rev  => $rev,
						  -user => $whoami);
			die "failed to lock config: $rv" if $rv;
		} else {
			die "failed to getConfig (trying to figure out 'rev'): $hv\n";
		}
	}
	print "# Configuration revision $rev locked for editing.\n";
}

if (exists $opts{'u'}) {
	if ($rev != 0) {
		my $hv = $np->db->isConfigLocked();
		
		if (ref($hv) ne "HASH" && ($hv =~ /db/)) {
			die "failed to query lock status: $hv\n";
		}

		if (ref($hv) ne "HASH" && ($hv == 0)) {
			print "# -u given but config is not locked.\n";
		} 
		elsif ($whoami ne $hv->{'user'}) {
			if (exists $opts{'f'}) {
				$rv = $np->db->unlockConfig(-rev => $rev, -user => $whoami);
				die "failed to force unlock config: $rv" if $rv;
				print "# Configuration revision $rev unlocked.\n";
			} else {
				die $hv->{'user'}. " holds the lock. use -f to force the unlock.\n";
			}
		}
		else {
			$rv = $np->db->unlockConfig(-rev => $rev, -user => $whoami);
			die "failed to unlock config: $rv" if $rv;
			print "# Configuration revision $rev unlocked.\n";
		}
	} else {
		# we dont know what the rev is

		my $hv = $np->db->getConfig();
		if ( (ref($hv) eq "HASH") && ($hv->{'rev'} > 0) ) {
			$rev = $hv->{'rev'};

			my $hv = $np->db->isConfigLocked();
		
			if (ref($hv) ne "HASH" && ($hv =~ /db/)) {
				die "failed to query lock status: $hv\n";
			}

			if (ref($hv) ne "HASH" && ($hv == 0)) {
				print "# -u given but config is not locked.\n";
			} 
			elsif ($whoami ne $hv->{'user'}) {
				if (exists $opts{'f'}) {
					$rv = $np->db->unlockConfig(-rev => $rev, -user => $whoami);
					die "failed to force unlock config: $rv" if $rv;
					print "# Configuration revision $rev unlocked.\n";
				} else {
					die $hv->{'user'}. " holds the lock. use -f to force the unlock.\n";
				}
			}
			else {
				$rv = $np->db->unlockConfig(-rev => $rev, -user => $whoami);
				die "failed to unlock config: $rv" if $rv;
				print "# Configuration revision $rev unlocked.\n";
			}
		} else {
			die "failed to getConfig (trying to figure out 'rev'): $hv\n";
		}
	}
}

$rv = $np->db->getConfig(-rev => $rev);

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
