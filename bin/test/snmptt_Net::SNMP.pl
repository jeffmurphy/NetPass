#!/usr/bin/perl  -w

use strict;
use Time::HiRes qw(gettimeofday tv_interval);
use Data::Dumper;

my ($sw, $cn) = (shift, shift);

my $oid = ".1.3.6.1.2.1.17.4.3.1.2";
#$oid = ".1.3.6.1.4.1.45.1.6.13.2.1.1.3";


my $ct;




use Net::SNMP;
$ct = [gettimeofday];
my ($s, $e) = Net::SNMP->session(-hostname  => $sw,
				 -version   => 2,
				 -community => $cn,
				 -timeout   => 15);
die "failed to create Net::SNMP session: $e" unless defined($s); 
print "created Net::SNMP session in ", tv_interval($ct), " seconds\n";


$ct = [gettimeofday];
my $result = $s->get_table(-baseoid => $oid, -maxrepetitions => 10);
print "fetched $oid table via Net::SNMP in ", tv_interval($ct), " seconds\n";

my @foo = keys %$result;
print "result $#foo\n";


exit 0;

