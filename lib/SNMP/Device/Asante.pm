# $Header: /tmp/netpass/NetPass/lib/SNMP/Device/Asante.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package SNMP::Device::Asante;

use SNMP::Device;
use Net::SNMP;

@ISA = ('SNMP::Device');

use strict;

sub restore {
	return 0;
}

sub backup {
	return 0;
}

sub get_unit_info {
	my $self = shift;

	my $stack_info = {};

	my $oids = {
			'sys_descr'	=> '.1.3.6.1.2.1.22.1.2.1.1.2',
		   };
	
        foreach my $oid (keys %$oids) {
               $self->_loadTable($oids->{$oid}, $oid, $stack_info);
        }

	return $stack_info;

}

sub get_if_info {
	my $self = shift;

	# Asante only has 2 units, 5 and 6
	my @units = (5,6);

	my $port_info = {};

	my $oids = {
			'port'	  	  => '.1.3.6.1.2.1.22.1.3.1.1.2',
        		
			'if_descr'        => '.1.3.6.1.2.1.22.1.3.1.1.2'
		   };

	foreach my $unit (@units) {
        	foreach my $oid (keys %$oids) {
                	$self->_loadPortTable($oids->{$oid}, $oid, $port_info, $unit);
        	}

		my $map = { 2=>1, 3=>2 };
                $self->_loadPortTable('.1.3.6.1.4.1.298.1.3.4.1.1.1.9', 'if_ad_status', $port_info, $unit, $map);
                $self->_loadPortTable('.1.3.6.1.4.1.298.1.3.4.1.1.1.4', 'if_status', $port_info, $unit, $map);
	}

	return $port_info;

}

sub _loadTable {
	my $self	= shift;	
	my $base_oid    = shift;
	my $desc        = shift;
	my $info	= shift;

	my $table = $self->snmp->get_table(-baseoid => $base_oid);
	if (!defined($table)) {
		foreach my $num(sort keys %{$info}) {
			$info->{$num}{$desc} = 'N/A';
		}
		return 0;
        }

	foreach my $k (keys %$table) {
        	$k =~ /(\d+)(\.0)*$/;
        	my $id = sprintf('%04d', $1);
		$info->{$id}{$desc} = $table->{$k};
	}

	return 1;
}

sub _loadPortTable {
	my $self	= shift;	
	my $base_oid    = shift;
	my $desc        = shift;
	my $info	= shift;
	my $unit	= shift;
	my $map		= shift;

	my $table = $self->snmp->get_table(-baseoid => "$base_oid.$unit");
	if (!defined($table)) {
		foreach my $num(sort keys %{$info}) {
			$info->{$num}{$desc} = 'N/A';
		}
		return 0;
        }

	foreach my $k (keys %$table) {
        	$k =~ /(\d+)(\.0)*$/;
        	my $id = sprintf('%04d', "$unit$1");

		if($map) {
			$info->{$id}{$desc}  = $map->{$table->{$k}};
		} else {
			$info->{$id}{$desc}  = $table->{$k};
		}
		$info->{$id}{'unit'} = $unit;
	}

	return 1;
}

1;

