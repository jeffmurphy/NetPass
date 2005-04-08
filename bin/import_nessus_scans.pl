#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/import_nessus_scans.pl,v 1.3 2005/04/08 20:08:10 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 import_nessus_scans.pl 

=head1 SYNOPSIS

 import_nessus_scans.pl 

=head1 DESCRIPTION

This script will connect to the nessus server, download the available
plugins and import them into the nessusScans table. It won't stomp 
on existing entries in that table. It isn't very clever about
how to connect to the nessus server. It's hardcoded right now.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Rob Colantuoni <rgc@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: import_nessus_scans.pl,v 1.3 2005/04/08 20:08:10 jeffmurphy Exp $

=cut


use strict;



# CREATE TABLE nessusScans (
#   pluginID int(10) unsigned NOT NULL default '0',
#   name varchar(255) default NULL,
#   family varchar(255) default NULL,
#   category varchar(255) default NULL,
#   short_desc varchar(255) default NULL,
#   description text,
#   addedBy varchar(32) NOT NULL default '',
#   addedOn timestamp(14) NOT NULL,
#   lastModifiedBy varchar(32) NOT NULL default '',
#   lastModifiedOn timestamp(14) NOT NULL,
#   status enum('enabled','disabled') default 'disabled',
#   info varchar(255) NOT NULL default 'nessus:',
#   revision varchar(255) default NULL,
#   copyright varchar(255) default NULL,
#   cve varchar(255) default NULL,
#   bugtraq varchar(255) default NULL,
#   other_refs varchar(255) default NULL,
#   PRIMARY KEY  (pluginID),
#   KEY status (status)
# ) TYPE=MyISAM;


use lib '/opt/netpass/lib';
use NetPass;
use NetPass::DB;
use Getopt::Std;

my %opts;
getopts('c:Dh?', \%opts);
if (exists $opts{'h'} || exists $opts{'?'}) {
	print "$0 [-h?D] [-c config]\n";
	exit 0;
}

my $D = exists $opts{'D'};

print "Loading Netpass object ..\n" if $D; 

my $np = new NetPass(-config => 
		     exists $opts{'c'} ? 
		     $opts{'c'} :
		     "/opt/netpass/etc/netpass.conf");


die "failed to load NetPass config" unless defined ($np);

print "Connecting to database ..\n" if $D;

my $netpass = new NetPass::DB($np->cfg->dbSource,
                              $np->cfg->dbUsername,
                              $np->cfg->dbPassword);

my $dbh = $netpass->{dbh};

print "Retrieving nessus configuration ..\n" if $D;
my $bd = $np->cfg->nessusBaseDir();

die "nessus base_dir undefined in netpass configuration"
  if (!defined($bd) || ($bd eq ""));

if (! -x "$bd/bin/nessus") {
	die "cant find $bd/bin/nessus";
}

my $host = $np->cfg->nessusHost();
my $user = $np->cfg->nessusUsername();
my $pass = $np->cfg->nessusPassword();
my $port = $np->cfg->nessusPort();

my $ncmd = "$bd/bin/nessus -q -p $host $port $user $pass "; 

print qq{Nessus command is: "$ncmd"\n} if $D;

open(FD, "$ncmd |") ||
  die qq{open of "$ncmd" failed: $!};

my $query = "INSERT IGNORE INTO nessusScans (pluginID, name, family, category, short_desc, description, addedBy, lastModifiedBy, revision, copyright, cve, bugtraq, other_refs) VALUES (?,?,?,?,?,?,'import','import',?,?,?,?,?)";

my $sth = $dbh->prepare($query);

print "Going into read loop ..\n" if $D;
while(my $l = <FD>) {
	print qq{Read: "$l"} if $D;

        my ($id, $family, $name, $category, $copyright, $shortDesc, $revision, $cveId, $bugtraqId, $references, $description) = split(/\|/, $l);

        $sth->execute($id, $name, $family, $category, $shortDesc, $description, $revision, $copyright, $cveId, $bugtraqId, $references);

}


$dbh->disconnect;

close(FD);

exit 0;
