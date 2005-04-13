#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/lsconf.pl,v 1.1 2005/04/13 20:57:43 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 lsconfig.pl  "list config(s)"

=head1 SYNOPSIS

 lsconfig.pl [-c cstr] [-U dbuser/dbpass] [-Dq] [-l rev]
     -c cstr        db connect string
     -U user/pass   db user[/pass]
     -D             enable debugging
     -q             quiet
     -l rev         show log for specified revision.

=head1 OPTIONS

 See above.

=head1 DESCRIPTION

List all configs in the database and details of each.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: lsconf.pl,v 1.1 2005/04/13 20:57:43 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;

my %opts;
getopts('c:U:l:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr  => exists $opts{'c'} ? $opts{'c'} : undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");


my $whoami = `/usr/bin/whoami`;
chomp($whoami);

my $hv = $np->db->listConfigs();
die $hv if ($hv ne "HASH" && ($hv =~ /db/));

if ($#{$hv->{'rev'}} == -1) {
	print "No configurations found in database.\n";
	exit 0;
}

my ($rev, $dt, $uid, $lck);

my $locks = 0;

$~ = "LS"; $^ = "LS_TOP";
for(my $row = 0; $row <= $#{$hv->{'rev'}} ; $row++) {
	$rev = $hv->{'rev'}->[$row];
	$dt  = scalar(localtime($hv->{'timestamp'}->[$row]));
	$uid = $hv->{'user'}->[$row];
	$lck = $hv->{'lock'}->[$row] ? "Y" : "";
	$locks++ if $lck;
	write;
}
$~ = "STDOUT"; $^ = "";

print "\nWarning: multiple locks detected. This shouldn't occur.
Use 'coconf' to unlock the config and it should clear the locks.\n" if $locks > 1;

if (exists $opts{'l'}) {
	my $hv = $np->db->getConfig(-rev => $opts{'l'});
	if (ref($hv) ne "HASH") {
		print qq{Failed to fetch revision "$opts{'l'}": $hv\n};
		exit 255;
	}
	print qq{\n\nLog for revision "$opts{'l'}":\n\n};
	print join("\n", @{$hv->{'log'}}), "\n";
}

exit 0;

format LS_TOP =
REV   CREATED              BYUSER             LOCKED?
-----------------------------------------------------
.

format LS =
@<<<< @<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<<  @<<<<<< 
$rev, $dt,                 $uid,              $lck
.

