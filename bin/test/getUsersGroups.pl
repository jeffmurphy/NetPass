#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/test/getUsersGroups.pl,v 1.1 2005/04/19 01:40:34 jeffmurphy Exp $
#


use strict;
use lib '/opt/netpass/lib';
use NetPass;
use Getopt::Std;

my %opts;
getopts('s:i:h', \%opts);

if (exists $opts{'h'}) {
	print "$0 -h\n";
	exit 0;
}

my $np = new NetPass();

my $ug = $np->db->getUsersAndGroups();

use Data::Dumper;
print Dumper ($ug);

exit 0;



