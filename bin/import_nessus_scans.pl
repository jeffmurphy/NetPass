#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/import_nessus_scans.pl,v 1.6 2005/08/22 19:26:06 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 import_nessus_scans.pl [-c cstr] [-U dbuser/dbpass] [-D]

=head1 SYNOPSIS

 import_nessus_scans.pl 

=head1 DESCRIPTION

This script will connect to the nessus server, download the available
plugins and import them into the nessusScans table. It won't stomp 
on existing entries in that table. 

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Rob Colantuoni <rgc@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: import_nessus_scans.pl,v 1.6 2005/08/22 19:26:06 jeffmurphy Exp $

=cut


use strict;

use lib '/opt/netpass/lib';
use NetPass;
use NetPass::DB;
use Getopt::Std;

my %opts;
getopts('c:U:Dh?', \%opts);
if (exists $opts{'h'} || exists $opts{'?'}) {
	print "$0 [-h?D] [-c config]\n";
	exit 0;
}

my $D = exists $opts{'D'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

$0 = "import_nessus_scans: connecting to NetPass";

print "Loading Netpass object ..\n" if $D; 

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} : undef,
		     -dbuser => $dbuser, -dbpass => $dbpass);


die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my $dbh = $np->db->{dbh};

print "Retrieving nessus configuration ..\n" if $D;
my $bd = $np->cfg->nessus(-key => 'base_dir');

die "nessus base_dir undefined in netpass configuration"
  if (!defined($bd) || ($bd eq ""));

if (! -x "$bd/bin/nessus") {
	die "cant find $bd/bin/nessus";
}

my $host = $np->cfg->nessus(-key => 'host');
my $user = $np->cfg->nessus(-key => 'username');
my $pass = $np->cfg->nessus(-key => 'password');
my $port = $np->cfg->nessus(-key => 'port');

my $ncmd = "$bd/bin/nessus -c /dev/null -x -q -p $host $port $user $pass "; 

print qq{Nessus command is: "$ncmd"\n} if $D;

$0 = "import_nessus_scans: connecting to Nessus";

open(FD, "$ncmd |") ||
  die qq{open of "$ncmd" failed: $!};

my $query = "INSERT IGNORE INTO nessusScans (pluginID, name, family, category, short_desc, description, addedBy, lastModifiedBy, revision, copyright, cve, bugtraq, other_refs) VALUES (?,?,?,?,?,?,'import','import',?,?,?,?,?)";

my $sth = $dbh->prepare($query);
my $sn  = 0;
print "Going into read loop ..\n" if $D;
while(my $l = <FD>) {
	$0 = "import_nessus_scans: importing scans ".$sn++;
	print qq{Read: "$l"} if $D;

        my ($id, $family, $name, $category, $copyright, $shortDesc, $revision, $cveId, $bugtraqId, $references, $description) = split(/\|/, $l);

        $sth->execute($id, $name, $family, $category, $shortDesc, $description, $revision, $copyright, $cveId, $bugtraqId, $references);

}


$dbh->disconnect;

close(FD);

exit 0;
