#!/usr/bin/perl -w
#
#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

proc_counter.pl - counts the number of netpass related procs
		  on each netpass server its run on

=head1 SYNOPSIS

 proc_counter.pl [-c config file]
     -c config file       location of netpass.conf
     -h                   this message

=head1 DESCRIPTION

This script should be run from cron every 10mins.

=AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=cut

use strict;
use Proc::ProcessTable;
use Getopt::Std;
use Sys::Hostname;
use Pod::Usage;

use lib qw{/opt/netpass/lib};
use NetPass::Config;
use NetPass::DB;

# processes to count
my $proc = {
                'mysqld'        => 0,
                'nessusd'       => 0,
                'httpd'         => 0,
           };

my %opts;
getopts('c:h?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my $cfg = new NetPass::Config(defined $opts{'c'} ? $opts{'c'} :
                              "/opt/netpass/etc/netpass.conf");

die "failed to create NetPass::Config object" unless defined $cfg;

my $dbh = new NetPass::DB($cfg->dbSource,
                          $cfg->dbUsername,
                          $cfg->dbPassword,
                          1);

if (!defined($dbh)) {
    print "failed to create NP:DB ".DBI->errstr."\n";
    exit 255;
}

my $onedayago = time() - 86400;

my $delete = "DELETE FROM stats_procs WHERE dt <= FROM_UNIXTIME($onedayago)";
my $insert = "INSERT INTO stats_procs (serverid, dt, proc, count) VALUES (?,NOW(),?,?)";
$dbh->{'dbh'}->do($delete);

my $sth = $dbh->{'dbh'}->prepare($insert);

my $t = new Proc::ProcessTable;

foreach my $p (@{$t->table}) {
	foreach my $s (keys %$proc) {
		if ($p->cmndline =~ /$s/) {
			$proc->{$s}++;
		}
	}
}

map ($sth->execute(hostname, $_, $proc->{$_}), keys %$proc);

$sth->finish;

exit 0;
