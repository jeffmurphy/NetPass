# $Header: /tmp/netpass/NetPass/lib/SNMP/Device/BayStack3.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package SNMP::Device::BayStack3;

use SNMP::Device;
use Net::SNMP;
use Bit::Vector;
use Data::Dumper;
use NetPass::LOG qw (_log _cont);

@ISA = ('SNMP::Device');

use strict;

=head1 NAME

SNMP::Device::BayStack3 - BayStack SNMP Controls

=head1 SYNOPSIS

This object is a subclass of L<|SNMP::Device> and shouldn't be used
directly. When a new SNMP::Device is created, it will return an
object of this type if it's appropriate.

=head1 SYNOPSIS

This object allows us to interface with the Nortel BayStack 350 switch

=head1 PUBLIC METHODS

=head2 B<init()>

        init is called immediately after the discovery of device type.
        this is an optional function and in this module, is used to set the
        snmp version to '2'

=cut

sub init {
        my $self        = shift;

        $self->log( ref($self) . "->init(): setting snmp version to '2'");
        $self->snmp_version('2');

        # set snmp to undef to force re-create on next snmp() call...
        # i'll find a nicer way to do this.. perhaps a snmp_refresh call or something
        $self->{_snmp} = undef;
        $self->log( ref($self) . "->init(): resetting snmp session");
        $self->snmp;

        return 1;
}

=head2 B<restore()>

	not implemented

=cut

sub restore {
	my $self 	= shift;
	return 0;
}

=head2 B<backup()>

	not implemented

=cut

sub backup {
	my $self 	= shift;
	return 0;
}

=head2 B<get_unit_info()>

	This will return a hash with the serial, description, and type of
	each unit in a stack.

=cut

sub get_unit_info {
	my $self = shift;

	my $stack_info = {};

        my $oids = {
                        'serial'    => '.1.3.6.1.4.1.45.1.6.3.3.1.1.7.3',
                        'sys_descr' => '.1.3.6.1.4.1.45.1.6.3.3.1.1.5.3',
                        'type'      => '.1.3.6.1.4.1.45.1.6.3.3.1.1.6.3'
                   };

        foreach my $oid (keys %$oids) {
                $self->_loadTable($oids->{$oid}, $oid, $stack_info);
        }
	
	$self->_loadSwFw($stack_info); 

	return $stack_info;

}

=head2 B<get_if_info()>

	This will return a hash with all interfaces and their information,
	including unit, port, admin status, operational status, autonegotiation,
	duplex, speed, fcs errors, vlan tagged/untagged, PVID, and member VLANS.

=cut

sub get_if_info {
	my $self = shift;

	my $port_info = {};


        my $oids = {
                        'port'            => '.1.3.6.1.4.1.45.1.6.5.3.12.1.2.1',
                        'if_descr'        => '.1.3.6.1.2.1.2.2.1.2',

                        'if_status'       => '.1.3.6.1.2.1.2.2.1.8',
                        'if_ad_status'    => '.1.3.6.1.2.1.2.2.1.7',

                        # 2 disabled, 1 enabled
                        'autoneg'         => '.1.3.6.1.4.1.2272.1.4.10.1.1.11',
                        'fcs_errors'      => '.1.3.6.1.2.1.10.7.2.1.3',
                   };

        foreach my $oid (keys %$oids) {
                $self->_loadTable($oids->{$oid}, $oid, $port_info);
        }

	# get unit number		
	foreach my $num(sort keys %{$port_info}) {
		$port_info->{$num}{'unit'} = 1;
	
		my $mod = $port_info->{$num}{'if_descr'};

		if($mod =~ /module\s+(\d+)/) {
			$port_info->{$num}{'unit'} = $1;
		}
		if($mod =~ /Unit\s+(\d+)/) {
			$port_info->{$num}{'unit'} = $1;
		}
	}

	return $port_info;

}

=head2 B<set_default_vlan_id(port, vlan)>

	Set the default VLAN that untagged packets will be placed into. If you want to
	I<add> a port to a VLAN, so that already tagged packets will be delivered to that port,
	use L<add_vlan_membership>. Returns 1 on success, 0 on failure.

=cut

sub set_default_vlan_id {
        my $self = shift;
        my $port = shift;
        my $vid  = shift;

        # nortel (450s, 470s, 5510 and late-model 350s)

        # RAPID-CITY::rcVlanPortNumVlanIds.24 = INTEGER: 1
        # RAPID-CITY::rcVlanPortNumVlanIds.25 = INTEGER: 3
        # RAPID-CITY::rcVlanPortVlanIds.24 = Hex-STRING: 03 2C
        # RAPID-CITY::rcVlanPortVlanIds.25 = Hex-STRING: 00 01 00 0C 03 2C
        # RAPID-CITY::rcVlanPortType.24 = INTEGER: access(1)
        # RAPID-CITY::rcVlanPortType.25 = INTEGER: trunk(2)
        # RAPID-CITY::rcVlanPortDefaultVlanId.24 = INTEGER: 12
        # RAPID-CITY::rcVlanPortDefaultVlanId.25 = INTEGER: 1

        # this one sets the default "PVID"

        # .iso.org.dod.internet.private.enterprises.rapidCity.rcMgmt.rcVlan.rcVlanPortTable.rcVlanPortEntry.rcVlanPortDefaultVlanId
        # .1.3.6.1.4.1.2272.1.3.3.1.3.7.PORT = integer
        # "meaningless when the port is not a trunk port" but we set it anyway since
        # tests indicate that it really is used even on 'access' ports.

        my $vlan_default_id = ".1.3.6.1.4.1.2272.1.3.3.1.7.$port";
        $self->snmp->set_request ($vlan_default_id, INTEGER, $vid);

        if($self->snmp->error) {
            #_log ("ERROR", "SNMP err". $self->snmp->error."\n");
            $self->err($self->snmp->error);
            return 0;
        }

        #_log ("DEBUG", "def id succ set to $vid\n") if $self->debug;
        return 1;
}

=head2 B<del_vlan_membership(port, id)>

	Remove the port from the specified VLAN. Preserve membership in other
	VLANs, if any. Returns: 0 on failure, 1 on success.

=cut

sub del_vlan_membership {
    	my ($self, $port, $id) = (shift, shift, shift);

    	#    rcVlanId OBJECT-TYPE
    	#        SYNTAX        INTEGER (1..4094)

    	return 0 if ($id < 1 || $id > 4094);

    	$self->snmp->translate(['-all' => 0]); #[ -octetstring => 0x0 ]);

    	# fetch bitfield

    	#PortSet         ::= OCTET STRING (SIZE (32))
    	# ...32 byte (256 bit)

    	my $oid = ".1.3.6.1.4.1.2272.1.3.2.1.11.$id";
    	my $vl  = $self->snmp->get_request($oid);

    	if($self->snmp->error) {
        	$self->err($self->snmp->error);
        	return 0;
    	}

    	#_log ("INFO", "Bit field[1]:".unpack('H*', $vl->{$oid})."\n") if $self->debug;

    	my $bv = Bit::Vector->new_Hex(256, unpack('H*', $vl->{$oid}));

    	# set our port bit to zero

    	#_log("INFO", "Bitfield[BEF]:\n".$bv->to_Bin()."\n") if $self->debug;

    	$bv->Bit_Off(255-$port); # MSB=port0, in B::V, MSB=bit255

    	#_log("INFO", "Bitfield[AFT]:\n".$bv->to_Bin()."\n") if $self->debug;

    	#_log ("INFO", "Bit field[2]:".$bv->to_Hex()."\n") if $self->debug;
    
	$self->snmp->set_request($oid, OCTET_STRING, pack('H*', $bv->to_Hex()));
    
	if($self->snmp->error) {
        	$self->err($self->snmp->error);
        	return 0;
    	}

    	return 1;
}

=head2 B<add_vlan_membership(port, id)>

	Add the port to the specified VLAN. Preserve membership in other VLANs,
	if any. Returns: 0 on failure, 1 on success.

=cut

sub add_vlan_membership {
    	my ($self, $port, $id) = (shift, shift, shift);

    	#    rcVlanId OBJECT-TYPE
    	#        SYNTAX        INTEGER (1..4094)

    	return 0 if ($id < 1 || $id > 4094);

    	# fetch bitfield

    	#PortSet         ::= OCTET STRING (SIZE (32))
    	# ...32 byte (256 bit)

    	my $oid = ".1.3.6.1.4.1.2272.1.3.2.1.11.$id";
    	my $vl  = $self->snmp->get_request($oid);

    	if($self->snmp->error) {
        	$self->err($self->snmp->error);
        	return 0;
    	}

    	#_log ("INFO", "Bit field[1]:".unpack('H*', $vl->{$oid})."\n") if $self->debug;

    	my $bv = Bit::Vector->new_Hex(256, unpack('H*', $vl->{$oid}));

    	# set our port bit to zero

    	#_log("INFO", "Bitfield:\n".$bv->to_Bin()."\n") if $self->debug;
    
	$bv->Bit_On(255-$port);
    
	#_log("INFO", "Bitfield:\n".$bv->to_Bin()."\n") if $self->debug;
	#_log ("INFO", "Bit field[2]:".$bv->to_Hex()."\n") if $self->debug;

    	$self->snmp->set_request($oid, OCTET_STRING, pack('H*', $bv->to_Hex()));
    
	if($self->snmp->error) {
        	$self->err($self->snmp->error);
        	return 0;
    	}

    	return 1;
}

=head2 B<check_if_tagged(port)>

	Check if port is a tagged trunk. Returns 1 if the port is tagged, 0 if
	untagged.

=cut

sub check_if_tagged {
    	my $self = shift;
    	my $port = shift;

    	my $oid = ".1.3.6.1.4.1.2272.1.3.3.1.4.$port";

    	my $res = $self->snmp->get_request ( $oid );
    	return ($res->{$oid} == 2) ? 1 : 0;
}

=head2 B<get_all_ports()>

	Retrieve the list of ports on this device. Return array reference on success
	or C<undef> on failure.

=cut

sub get_all_ports {
        my $self = shift;
        my @ports;

        my $oid   = ".1.3.6.1.2.1.2.2.1.1";
        my $oid_n = $oid;

        while (1) {
                my $res = $self->snmp->get_next_request(-varbindlist => [$oid_n]);
                return undef if !$res;

                $oid_n = (keys(%$res))[0];

                last if ($oid ne substr($oid_n, 0, length($oid)));
                push @ports, $res->{$oid_n};
        }

        return \@ports;
}

=head2 B<get_vlan_membership(port)>

	Retrieve the list of VLANs that this port is a member of. Return them via
	an array reference. Return array reference on success or C<undef> on failure.

=cut

sub get_vlan_membership {
        my $self = shift;
        my $port = shift;

        $self->snmp->translate(['-all' => 0]); #[ -octetstring => 0x0 ]);

        my $oid = ".1.3.6.1.4.1.2272.1.3.3.1.3.$port";

        my $vid = $self->snmp->get_request ( $oid );

        if($self->snmp->error) {
            	$self->err($self->snmp->error);
            	return undef;
        }
        #_log("DEBUG",  "port $port membership: ".length($vid->{$oid})."  ".unpack('H*', $vid->{$oid})."\n") if($self->debug);

        my @vs;
        for (my $i = 0; $i < length($vid->{$oid}); $i+=2) {
            push @vs, hex(unpack('H*', substr($vid->{$oid}, $i, 2)));
        }

        return \@vs;
}

=head2 B<get_default_vlan_id(port)>

	For trunked ports, this is the vlan that incoming untagged packets are
	tagged into. Nortel calls this "PVID". Returns: the PVID (positive integer)
	on success, B<0 on failure>.

=cut

sub get_default_vlan_id {
        my $self = shift;
        my $port = shift;

        $self->snmp->translate([ -all => 0x0 ]);

        my $vlan_default_id = ".1.3.6.1.4.1.2272.1.3.3.1.7.$port";

        my $vid = $self->snmp->get_request ($vlan_default_id);

        if($self->snmp->error) {
            $self->err($self->snmp->error);
            return 0;
        }

        return $vid->{$vlan_default_id};
}

=head2 B<($mp, $pm) = get_mac_port_table()>

	Fetch the MAC-to-Port mapping using the bridge mib (rfc1493). Returns two HASH REFs
	(\%mac_to_port, \%port_to_mac) on success, C<undef> on failure.

=cut

sub get_mac_port_table {
	my $self = shift;

    	# .iso.org.dod.internet.mgmt.mib-2.ip.ipNetToMediaTable
    	# .1.3.6.1.2.1.4.22

    	# .iso.org.dod.internet.mgmt.mib-2.at.atTable
   	# .1.3.6.1.2.1.3.1

    	# .iso.org.dod.internet.mgmt.mib-2.dot1dBridge.dot1dTp.dot1dTpFdbTable.dot1dTpFdbEntry.dot1dTpFdbPort
    	# .1.3.6.1.2.1.17.4.3.1.2


    	my $m2p = {};
    	my $p2m = {};
    	my $res;
    	my $oid = ".1.3.6.1.2.1.17.4.3.1.2";

    	if (!defined($res = $self->snmp->get_table($oid))) {
        	$self->err($self->snmp->error);
        	return undef;
    	}

  	MAC: foreach my $key (keys %{$res}) {

        	my ($m1, $m2, $m3, $m4, $m5, $m6) = 
		($key =~ /^.*?\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); # MAC pieces, base 10.
        	
		my $mac = 	sprintf("%2.2x", $m1) .
          			sprintf("%2.2x", $m2) .
          			sprintf("%2.2x", $m3) .
          			sprintf("%2.2x", $m4) .
          			sprintf("%2.2x", $m5) .
          			sprintf("%2.2x", $m6);

        	my $ifIndex = $res->{$key};

        	if (defined ($ifIndex)) {
            		$m2p->{$mac} = [] if !exists $m2p->{$mac};
            		$p2m->{$ifIndex} = [] if !exists $p2m->{$ifIndex};
            		push @{$m2p->{$mac}}     , $ifIndex;
            		push @{$p2m->{$ifIndex}} , $mac;
        	}
    	}

    	return ($m2p, $p2m);
}


# PRIVATE MEMBERS

sub _loadTable {
	my $self	= shift;	
	my $base_oid    = shift;
	my $desc        = shift;
	my $info	= shift;

	my $table = $self->snmp->get_table(-baseoid => $base_oid);
	if (!defined($table)) {
		$table = $self->snmp->get_table(-baseoid => $base_oid);
		if (!defined($table)) {
			foreach my $num(sort keys %{$info}) {
				$info->{$num}{$desc} = 'N/A';
			}
			return 0;
		}
        }

	foreach my $k (keys %$table) {
        	$k =~ /(\d+)(\.0)*$/;
        	my $id = sprintf('%04d', $1);
		$info->{$id}{$desc} = $table->{$k};
	}

	return 1;
}

sub _loadSwFw {
	my $self	= shift;
	my $info	= shift;

        my $base_oid    = '.1.3.6.1.4.1.45.1.6.3.5.1.1.7';

        my $table = $self->snmp->get_table(-baseoid => $base_oid);

	foreach my $num(sort keys %{$info}) {
		$info->{$num}{'firmware'} = 'N/A';
		$info->{$num}{'software'} = 'N/A';
	}
	return 0 if (!defined($table)); 

        foreach my $k (keys %$table) {
        	$k =~ /(\d+)(\.0\.\d)*$/;

                my $id = sprintf("%04d", $1);
		if($2 eq ".0.1") {
			$info->{$id}{'software'} = $table->{$k};
		} elsif ($2 eq ".0.2") {
			$info->{$id}{'firmware'} = $table->{$k};
		} else {

		}
        }
        return 1;

} # end _loadSwFw


=head2 B<$port = get_mac_port($mac)>

 Given a MAC address, determine if it's on the current switch. If it is,
 return the port number, otherwise return C<undef>

=cut

sub get_mac_port {
        my $self = shift;
        my $mac  = shift;
	my $decmac = HexMac2DecMac($mac);
	my $mac_table_oid = '.1.3.6.1.2.1.17.4.3.1.2'; # SNMPv2-SMI::mib-2.17.4.3.1.2

	my $response = $self->snmp->get_request ("$mac_table_oid.$decmac");
	if ($self->snmp->error) {
		$self->err($self->snmp->error);
		_log("ERROR", "$mac get_request failed ".$self->snmp->error."\n");
		return undef;
	}
        return $response->{"$mac_table_oid.$decmac"};
}


=head2 B<($module, $port) = get_ifDesc($ifIndex)>

 Given an ifIndex, return the module and port that it corresponds too. This is
 used by the topology search routine (get_next_switch).

=cut

sub get_ifDesc {
	my $self       = shift;
	my $ifIndex    = shift;


	# 350's dont stack. so just return the $ifIndex.

	return (1, $ifIndex);


	my $ifDescBase = "1.3.6.1.2.1.2.2.1.2";

	my $oid = $ifDescBase.".".$ifIndex;

	#_log("DEBUG", "get_ifDesc($ifIndex) oid=$oid\n");
	my $response = $self->snmp->get_request ($oid);
	#_log("DEBUG", "get_ifDesc($ifIndex) resp=", Dumper($response), "\n");


	if ($self->snmp->error) {
		$self->err($self->snmp->error);
		_log("ERROR", "get_request($oid) failed ".$self->snmp->error."\n");
		return undef;
	}

	if ($response->{$oid} eq "noSuchInstance") {
		_log("ERROR", "get_request($oid) returned noSuchInstance\n");
		return undef;
	}

	# .1.3.6.1.2.1.2.2.1.2.1 = STRING: BayStack - module 1, port 1

	if ($response->{$oid} =~ /BayStack\s350.*\s\-\s(\d+)/) {
		return ($1, $2);
	}

	_log("ERROR", "could not parse module/port out of \"",
	     $response->{$oid}, "\"\n");
	return undef;
}

=head2 B<$ip = get_next_switch($ifIndex)>

 Given a port, determine if there's a switch attached to it. 

 ON SUCCESS RETURNS
       Either and IP address of the next switch or ""
 ON FAILURE RETURNS
       C<undef>

 Pay attention to the return value. "" means there is no 
 downstream switch. C<undef> means there was an SNMP failure.

=cut

sub get_next_switch {
	my $self    = shift;
	my $ifIndex = shift;

	my $topo_oid = '.1.3.6.1.4.1.45.1.6.13.2.1.1.3'; # S5-ETH-MULTISEG-TOPOLOGY-MIB::s5EnMsTopNmmIpAddr

	my $response = $self->snmp->get_table (-baseoid        => "$topo_oid",
					       -maxrepetitions => 10); # populate hash

	if ($self->snmp->error) {
		_log("ERROR", "get_table failed for ",
		     $self->ip, " if=$ifIndex ".$self->snmp->error."\n");
		return undef;
	}

	#_log("DEBUG",  "topo \n", Dumper($response), "\n");
	
	my ($targetModule, $targetPort) = $self->get_ifDesc($ifIndex);

	#_log("DEBUG", "target for $ifIndex is $targetModule $targetPort\n");

	foreach my $key (keys %{$response}) {
		my ($slot, $port, $next_ip, $seg_id) = ($key =~ /^$topo_oid\.
								 (\d{1,3})\. # slot
								 (\d{1,3})\. # port
								 (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\. # next_ip
								 (\d{1,3}) # segment id
								 $/x);
		
		return $next_ip if ( ($slot == $targetModule) && 
				     ($port == $targetPort) );
	}
        return "";
}

=head2 $dm = HexMac2DecMac($hm)

This routine takes a mac address in hex format (e.g. 00FF00FF00FF) and
returns it in decimal format (0.255.0.255.0.255). This is useful when certain
OIDs contain mac address... .1.3.6.4.9999.2.1.0.255.0.255.0.255 = ...

=cut

sub HexMac2DecMac {

   my $hex_mac = shift; # hexadecimal mac in raw 12-character format (no : or - separators). 
   my $dec_mac = ''; # rv

   my ($m1, $m2, $m3, $m4, $m5, $m6) = ($hex_mac =~ /^(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})$/); # MAC pieces, base 16.

   $m1 = hex($m1);
   $m2 = hex($m2);
   $m3 = hex($m3);
   $m4 = hex($m4);
   $m5 = hex($m5);
   $m6 = hex($m6);

   return "$m1.$m2.$m3.$m4.$m5.$m6"; # decimal equivalent of hexadecimal mac address.
}

=head1 AUTHOR

 Rob Colantuoni <rgc@buffalo.edu>
 Jeff Murphy <jcmurphy@buffalo.edu>
 Chris Miller <cwmiller@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: BayStack3.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

=cut



1;
