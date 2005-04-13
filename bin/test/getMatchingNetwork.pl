#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/test/getMatchingNetwork.pl,v 1.1 2005/04/13 20:57:43 jeffmurphy Exp $
#


use strict;
use lib '/opt/netpass/lib';
use NetPass;
use Getopt::Std;

my %opts;
getopts('s:i:h', \%opts);

if (exists $opts{'h'}) {
	print "$0 -s switch/port -i ipaddress -h\n";
	exit 0;
}

my $np = new NetPass();

if (exists $opts{'i'}) {
	my $n = $np->cfg->getMatchingNetwork(-ip => $opts{'i'});
	print qq{Matching network for $opts{'i'} is $n\n};
} else {
	my ($s, $p) = (split('/', $opts{'s'}));
	die "bad switch/port specified. no '/' found\n" 
	  unless (defined($s) && defined($p));

	my $n = $np->cfg->getMatchingNetwork(-switch => $s, -port => $p);
	print qq{Matching network for $s/$p is $n\n};
}

exit 0;

