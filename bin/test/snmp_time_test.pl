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


use SNMP;

$ct = [gettimeofday];
my $s = new SNMP::Session(DestHost => $sw, Community => $cn, Version => 2);
print "created SNMP::Session in ", tv_interval($ct), " seconds\n";
die "failed to create SNMP::Session $SNMP::ErrorStr" unless defined($s);
my $e;
my $vars = new SNMP::VarList( [$oid] );


$ct = [gettimeofday];
my $resp = $s->bulkwalk(0, 10, $vars);
die "SNMP::bulkwalk failed ".$s->ErrorStr unless defined($resp);
print "fetched $oid table via SNMP::Session in ", tv_interval($ct), " seconds\n";
print Dumper($resp), "\n\n";


use Net::SNMP;
$ct = [gettimeofday];
($s, $e) = Net::SNMP->session(-hostname => $sw,
				 -version  => 2,
				 -community => $cn);
die "failed to create Net::SNMP session: $e" unless defined($s); 
print "created Net::SNMP session in ", tv_interval($ct), " seconds\n";


$ct = [gettimeofday];
my $result = $s->get_table(-baseoid => $oid);
die "get_table failed ".$s->error unless defined($result);
print "fetched $oid table via Net::SNMP in ", tv_interval($ct), " seconds\n";

print Dumper($result), "\n\n";


exit 0;

# via C in 2.567913 seconds
# via SNMP::Session in 2.683204 seconds
# via Net::SNMP in 2.322424 seconds
