#!/usr/bin/perl -w

# $Header: /tmp/netpass/NetPass/lib/SNMP/driver2.pl,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

use lib '/opt/netpass/lib';
use SNMP::Device;

use strict;

my $ip   = shift;
my $comm = shift;

# create new Device Snapshot object from SNMP
my $dev = new SNMP::Device (
					'hostname'	 => $ip,
					'snmp_community' => $comm,
			      	    );

print "\nDevice $ip has the following units:\n";

my $unit_info = $dev->unit_info();

foreach my $unit (keys %{$unit_info}) {

        print "$unit";
	print " - " . $unit_info->{$unit}->{'sys_descr'} if($unit_info->{$unit}->{'sys_descr'});
	print "\n";

}
print "\n\n";

print "debug output:\n";

print $dev->log . "\n" if($dev->log);
print $dev->err . "\n" if($dev->err);

exit;
