#!/usr/bin/perl  -w

use strict;
use Time::HiRes qw(gettimeofday tv_interval);
use Data::Dumper;

my ($sw, $cn) = (shift, shift);

my $oid = ".1.3.6.1.2.1.17.4.3.1.2";
$oid = ".1.3.6.1.4.1.45.1.6.13.2.1.1.3";


my $ct;



use SNMP;

$SNMP::debugging = 1;

$ct = [gettimeofday];
my $s = new SNMP::Session(DestHost => $sw, Community => $cn, Version => 2, Timeout => 15000000);
print "created SNMP::Session in ", tv_interval($ct), " seconds\n";
die "failed to create SNMP::Session $SNMP::ErrorStr" unless defined($s);
my $e;

my $vars = new SNMP::VarList( [$oid] );


$ct = [gettimeofday];
my @resp = $s->bulkwalk(0, 10, $vars);
die "SNMP::bulkwalk failed ".$s->ErrorStr unless @resp;
print "e ".$s->{'ErrorStr'}."\n";
print "fetched $oid table via SNMP::Session in ", tv_interval($ct), " seconds\n";
print Dumper(@resp), "\n\n";




exit 0;

