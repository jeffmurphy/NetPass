#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/test/policy.pl,v 1.1 2005/04/14 18:32:12 jeffmurphy Exp $
#
# jcm

use strict;
use lib '/opt/netpass/lib';
use NetPass;
use NetPass::LOG qw(_log _cont);
NetPass::LOG::init *STDOUT;

my $np = new NetPass(-debug => 3);
my $pv = shift;
my $nw = shift;

die "usage: $0 [policy var]\n" unless defined($pv);

print "Resolving $pv ..\n";

my $val = $np->cfg->policy($pv, $nw);

print "$pv = $val\n";

exit 0;

