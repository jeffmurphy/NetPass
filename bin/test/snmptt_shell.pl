#!/usr/bin/perl  -w

use strict;
use Time::HiRes qw(gettimeofday tv_interval);
use Data::Dumper;

my ($sw, $cn) = (shift, shift);

my $oid = ".1.3.6.1.2.1.17.4.3.1.2";
$oid = ".1.3.6.1.4.1.45.1.6.13.2.1.1.3";


my $ct;



my $command = qq{/usr/local/net-snmp-5.0.8/bin/snmpbulkwalk -v 2c -c $cn $sw $oid };
print "command = $command\n";
$ct = [gettimeofday];
#system($command);
system("$command 2>&1 > /dev/null");
print "fetched $oid table via C in ", tv_interval($ct), " seconds\n";


exit 0;

