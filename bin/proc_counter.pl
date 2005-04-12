#!/opt/perl/bin/perl -w
#
#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

proc_counter.pl - counts the number of netpass related procs
		  on each netpass server its run on

=head1 SYNOPSIS

 proc_counter.pl [-c cstr] [-U user/pass] [-qDh?]
     -c cstr              db connect string
     -U user/pass         db user[/pass]
     -q                   quiet
     -D                   debug
     -h -?                this message

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
use NetPass;

# processes to count
my $proc = {
                'mysqld'        => 0,
                'nessusd'       => 0,
                'httpd'         => 0,
           };

my %opts;
getopts('c:h?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my $onedayago = time() - 86400;

my $delete = "DELETE FROM stats_procs WHERE dt <= FROM_UNIXTIME($onedayago)";
my $insert = "INSERT INTO stats_procs (serverid, dt, proc, count) VALUES (?,NOW(),?,?)";
$np->db->{'dbh'}->do($delete);

my $sth = $np->dbh->{'dbh'}->prepare($insert);

my $t = new Proc::ProcessTable;

foreach my $p (@{$t->table}) {
	foreach my $s (keys %$proc) {
		if ($p->cmndline =~ /$s/) {
			$proc->{$s}++;
			last;
		}
	}
}

map ($sth->execute(hostname, $_, $proc->{$_}), keys %$proc);

$sth->finish;

exit 0;
