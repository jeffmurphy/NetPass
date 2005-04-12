#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/mysql_binlog_rotate.pl,v 1.4 2005/04/12 15:24:08 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

mysql_binlog_rotate.pl - purges mysql binlogs

=head1 SYNOPSIS

 mysql_binlog_rotate.pl [-c config file]
     -c config file       location of netpass.conf
     -h                   this message

=head1 DESCRIPTION

This script should be run from cron.monthly.

=head1 SEE ALSO

C<doc/cron.monthly/mysql_binlog_rotate>

=AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: mysql_binlog_rotate.pl,v 1.4 2005/04/12 15:24:08 jeffmurphy Exp $

=cut


use strict;
use DBI;
use Getopt::Std;
use Pod::Usage;

use lib '/opt/netpass/lib';
use NetPass;

my $MINLOGS = 10;

my %opts;
getopts('c:h?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my $dbh = $np->db->{'dbh'};

my $logs = $dbh->selectall_arrayref("SHOW MASTER LOGS");
die "Unable to get binlogs" unless defined $logs;

my $last_log = $logs->[-$MINLOGS];
my $purge    = "PURGE MASTER LOGS TO '".$last_log->[0]."'"; 

$dbh->do($purge) || die "Unable to purge binlog files from mysql";

exit 0;
