#!/usr/bin/perl -w

# $Header: /tmp/netpass/NetPass/lib/SNMP/driver3.pl,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


use lib '/opt/netpass/lib';
use SNMP::Device;

use strict;

my $ip   = shift;
my $comm = shift;

print "$ip\n";

# create new Device Snapshot object from SNMP
my $dev = new SNMP::Device (
					'hostname'	 => $ip,
					'snmp_community' => $comm,
					'sys_desc'	 => 'BayStack 450'
			      	    );

print $dev->log . "\n" if($dev->log);
print $dev->err . "\n" if($dev->err);

exit;
