#!/opt/perl/bin/perl -w

use strict;
use lib '/opt/netpass/lib';
use NetPass::Config;

my $h = {
	 '12/812' => [ 1,2,3,10,11,12,20 ],
	 '13/813' => [ 4,5,6,24,28,29,30 ]
	 };

print NetPass::Config::formatPorts($h), "\n";

exit 0;
