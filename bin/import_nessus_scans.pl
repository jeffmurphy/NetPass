#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/import_nessus_scans.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

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

$Id: import_nessus_scans.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

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


my $np = new NetPass(-config => "/opt/netpass/etc/netpass.conf");
my $netpass = new NetPass::DB($np->cfg->dbSource,
                                     $np->cfg->dbUsername,
                                     $np->cfg->dbPassword);

my $dbh = $netpass->{dbh};

open(FD, "/opt/nessus/bin/nessus -q -p localhost 1241 netpass netpass |") ||
  die "open failed $!";

my $query = "INSERT IGNORE INTO nessusScans (pluginID, name, family, category, short_desc, description, addedBy, lastModifiedBy, revision, copyright, cve, bugtraq, other_refs) VALUES (?,?,?,?,?,?,'import','import',?,?,?,?,?)";

my $sth = $dbh->prepare($query);

while(my $l = <FD>) {

        my ($id, $family, $name, $category, $copyright, $shortDesc, $revision, $cveId, $bugtraqId, $references, $description) = split(/\|/, $l);

        $sth->execute($id, $name, $family, $category, $shortDesc, $description, $revision, $copyright, $cveId, $bugtraqId, $references);

}


$dbh->disconnect;

close(FD);

exit 0;
