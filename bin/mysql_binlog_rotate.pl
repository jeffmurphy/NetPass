#!/usr/bin/perl
#
# $Header: /tmp/netpass/NetPass/bin/mysql_binlog_rotate.pl,v 1.2 2004/10/12 17:28:04 mtbell Exp $

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

$Id: mysql_binlog_rotate.pl,v 1.2 2004/10/12 17:28:04 mtbell Exp $

=cut


use strict;
use DBI;
use Getopt::Std;
use Pod::Usage;

use lib '/opt/netpass/lib';
use NetPass::Config;

my $MINLOGS = 10;

my %opts;
getopts('c:h?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $cfg = new NetPass::Config(defined $opts{'c'} ? $opts{'c'} : 
			      "/opt/netpass/etc/netpass.conf");
die "Cannot get NetPass::Config object" unless defined $cfg;

my $cstr = sprintf("dbi:mysql:database=%s;host=%s", $cfg->dbSource, 'localhost');

my $dbh = DBI->connect($cstr, $cfg->dbUsername, $cfg->dbPassword);
die "Cannot connect to database" unless defined $dbh;

my $logs = $dbh->selectall_arrayref("SHOW MASTER LOGS");
die "Unable to get binlogs" unless defined $logs;

my $last_log = $logs->[-$MINLOGS];
my $purge    = "PURGE MASTER LOGS TO '".$last_log->[0]."'"; 

$dbh->do($purge) || die "Unable to purge binlog files from mysql";

exit 0;
