package SNMP::Device::Cisco;

use SNMP::Device;
use NetPass::Config;
use Net::SNMP;
use NetPass::LOG qw (_log _cont);

@ISA = ('SNMP::Device');
use strict;
=head1 NAME

NetPass::SNMP::Cisco - Cisco SNMP Controls

=head1 SYNOPSIS

This object is a subclass of L<|NetPass::SNMP> and shouldn't be used 
directly.

=head1 SYNOPSIS

This object allows us to interface with the various Cisco switches.

=head1 METHODS

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

=head2 set_default_vlan_id(port, vlan)

Cisco doesn't have this equilivent.  Just return true if called.

=cut

sub set_default_vlan_id {
	my $snmp = shift;
	my $port = shift;
	my $vid	 = shift;

	return 1;
}

=head2 del_vlan_membership(port, id)

Remove the port from the specified VLAN. Preserve membership in other
VLANs, if any. Returns: 0 on failure, 1 on success.

Don't use multiple vlans for our Cisco equipment, just return true. No need 
to delete vlan, since only only is permitted.  add_vlan_membership will 
replace the vlan.
=cut

sub del_vlan_membership {
    my ($snmp, $port, $id) = (shift, shift, shift);

    return 1;
}

=head2 add_vlan_membership(port, id)

Add the port to the specified VLAN. Preserve membership in other VLANs,
if any. Returns: 0 on failure, 1 on success.

=cut

sub add_vlan_membership {
    my ($snmp, $port, $id) = (shift, shift, shift);

    #    vmVlan OBJECT-TYPE
    #        SYNTAX        INTEGER (0..4095)

    return 0 if ($id < 0 || $id > 4095);



    my $oid = ".1.3.6.1.4.1.9.9.68.1.2.2.1.2.$port";

    $snmp->snmp->set_request($oid, INTEGER, $id);
    if($snmp->snmp->error) {
	$snmp->err($snmp->snmp->error);
	return 0;
    }

    return 1;
}

=head2 get_vlan_membership(port)

Retrieve the list of VLANs that this port is a member of. Return them via
an array reference. Return array reference on success or C<undef> on failure.

=cut

sub get_vlan_membership {
	my $snmp = shift;
	my $port = shift;

	$snmp->snmp->translate(['-all' => 0]); #[ -octetstring => 0x0 ]);

	my $oid = ".1.3.6.1.4.1.9.9.68.1.2.2.1.2.$port";

	my $vid = $snmp->snmp->get_request ( $oid );

	if($snmp->snmp->error) {
	    $snmp->err($snmp->snmp->error);
	    return undef;
	}
	_log("DEBUG",  "port $port membership: ".length($vid->{$oid})."\n") if($snmp->debug);

	my @vs;
	push @vs, $vid->{$oid};

	return \@vs;
}

=head2 get_default_vlan_id(port)

For trunked ports, this is the vlan that incoming untagged packets are
tagged into. Nortel calls this "PVID". Returns: the PVID (positive integer)
on success, B<0 on failure>.

=cut

sub get_default_vlan_id {
	my $snmp = shift;
	my $port = shift;

	$snmp->snmp->translate([ -all => 0x0 ]);

	my $vlan_default_id = ".1.3.6.1.4.1.2272.1.3.3.1.7.$port";

	my $vid = $snmp->snmp->get_request ($vlan_default_id);
	
	if($snmp->snmp->error) {
	    $snmp->err($snmp->snmp->error);
	    return 0;
	}

	return $vid->{$vlan_default_id};
}

=head2 ($mp, $pm) = get_mac_port_table()

Fetch the MAC-to-Port mapping using the bridge mib (rfc1493). Returns two HASH REFs
(\%mac_to_port, \%port_to_mac) on success, C<undef> on failure.

=cut

sub get_mac_port_table {
    my $snmp = shift;

    # .iso.org.dod.internet.mgmt.mib-2.ip.ipNetToMediaTable
    # .1.3.6.1.2.1.4.22

    # .iso.org.dod.internet.mgmt.mib-2.at.atTable
    # .1.3.6.1.2.1.3.1

    # .iso.org.dod.internet.mgmt.mib-2.dot1dBridge.dot1dTp.dot1dTpFdbTable.dot1dTpFdbEntry.dot1dTpFdbPort
    # .1.3.6.1.2.1.17.4.3.1.2


    my $m2p = {};
    my $p2m = {};
    my $res;
    my $resp;
    my $oid = ".1.3.6.1.2.1.17.4.3.1.2";
    my $lcloid = ".1.3.6.1.2.1.17.4.3.1.3";
    my $vlanoid = ".1.3.6.1.4.1.9.9.68.1.2.2.1.2";
    my $p2ifoid = ".1.3.6.1.2.1.17.1.4.1.2";
# Check to see what mac's are for the switch

    my %selfhash = ();
    my $reslcl = $snmp->snmp->get_table(-baseoid=>$lcloid);
    foreach my $selfoid (keys(%{$reslcl})){
	if ($reslcl->{$selfoid} == 4){
	    my @selfoidtmp = split(/\./,$selfoid);
	    $selfoidtmp[11] = "2";
	    my $selfoid = join('.',@selfoidtmp);
	    $selfhash{$selfoid} = 1;
	}
    }

# Create hash of vlans that are on ports
    if (!defined($res = $snmp->snmp->get_table($vlanoid))) {
        $snmp->err($snmp->snmp->error);
        return undef;
    }
    my %vlanhash;
    foreach my $void (keys(%{$res})) {
	my $vlan = $res->{$void};
	$vlanhash{$vlan} = 1;
    }
    my $orig_cn = $snmp->snmp_community;
    foreach my $vlan (keys(%vlanhash)) {
	$snmp->snmp_community("$orig_cn\@$vlan");
	my $snmp2 = $snmp->_create_snmp();
	
# create bridge port to ifindex mapping hash
	
	if (!defined($resp = $snmp2->get_table($p2ifoid))) {
	    $snmp->err($snmp2->error);
	    return undef;
        }
	my %p2ihash = ();
	foreach my $p2ioid (keys(%{$resp})) {
	    my $bport = substr($p2ioid,rindex($p2ioid,".")+1);
	    $p2ihash{$bport} = $resp->{$p2ioid};
        }
	if (!defined($res = $snmp2->get_table($oid))) {
	    $snmp->err($snmp2->error);
	    $snmp->snmp_community($orig_cn);
	    #return undef;
	}
	
	
      MAC: foreach my $key (keys %{$res}) {
	  if (exists($selfhash{$key})){
	      next;
	  }
	  my ($m1, $m2, $m3, $m4, $m5, $m6) = ($key =~ /^.*?\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); # MAC pieces, base 10.
	  my $mac = sprintf("%2.2x", $m1) .
	      sprintf("%2.2x", $m2) .
	      sprintf("%2.2x", $m3) .
	      sprintf("%2.2x", $m4) .
	      sprintf("%2.2x", $m5) .
	      sprintf("%2.2x", $m6);
	  
	  my $ifIndex = $p2ihash{$res->{$key}};
	  if (defined ($ifIndex)) {
	      $m2p->{$mac} = [] if !exists $m2p->{$mac};
	      $p2m->{$ifIndex} = [] if !exists $p2m->{$ifIndex};
	      push @{$m2p->{$mac}}     , $ifIndex;
	      push @{$p2m->{$ifIndex}} , $mac;
	  }
      } # vlan foreach
    } # mac foreach
    $snmp->snmp_community($orig_cn);
    
    return ($m2p, $p2m);
}

=head2 B<$port = get_mac_port($mac)>

 Given a MAC address, determine if it's on the current switch. If it is,
 return the port number, otherwise return C<undef>

=cut

sub get_mac_port {
        my $self = shift; 
        my $mac  = shift;
        my $myNW  = shift;
        my $decmac = HexMac2DecMac($mac);
        my $mac_table_oid = '.1.3.6.1.2.1.17.4.3.1.2'; # SNMPv2-SMI::mib-2.17.4.3.1.2
        my $oid = ".1.3.6.1.2.1.17.4.3.1.2";
        my $vlanoid = ".1.3.6.1.4.1.9.9.68.1.2.2.1.2";
        my $p2ifoid = ".1.3.6.1.2.1.17.1.4.1.2";
        my ($res,$resp,$res1);

# Need to get unquar and quar vlans for network, otherwise would need to go
# through all the vlans on the switch.

	my $np = new NetPass(-cstr   =>  undef,
                     		-dbuser => '', -dbpass => '',
                	    	-debug  => 0,
                     		-quiet  => 0);

    	my @taglist = $np->cfg->availableVlans(-network=>$myNW);
    	my $orig_cn = $self->snmp_community;
    	foreach my $vlan (@taglist) {
      		$self->snmp_community("$orig_cn\@$vlan");
      		my $snmp2 = $self->_create_snmp();

		# create bridge port to ifindex mapping hash

		if (!defined($resp = $snmp2->get_table($p2ifoid))) {
			$self->err($snmp2->error);
			return undef;
		}
		my %p2ihash = ();
		foreach my $p2ioid (keys(%{$resp})) {
			my $bport = substr($p2ioid,rindex($p2ioid,".")+1);
			$p2ihash{$bport} = $resp->{$p2ioid};
		}
		if (!defined($res1 = $snmp2->get_request("$oid.$decmac"))) {
			next;
		}
		if ($res1->{"$oid.$decmac"} =~ /\d+/){
			$self->snmp_community($orig_cn);
			return $p2ihash{$res1->{"$oid.$decmac"}};
		}
		else {
			next;
		}
	}
	$self->snmp_community($orig_cn);
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

        my $topo_oid = ".1.3.6.1.4.1.9.9.23.1.2.1.1.4.$ifIndex";

        my $response = $self->snmp->get_table (-baseoid        => "$topo_oid",
                                               -maxrepetitions => 10); # populate hash

        if ($self->snmp->error) {
                _log("ERROR", "get_table failed for ",
                     $self->ip, " if=$ifIndex ".$self->snmp->error."\n");
                return undef;
        }

        foreach my $key (keys %{$response}) {
		my $hexip = $response->{$key};
		push(my @ip,hex(substr($hexip,2,2)));
		push(@ip,hex(substr($hexip,4,2)));
		push(@ip,hex(substr($hexip,6,2)));
		push(@ip,hex(substr($hexip,8,2)));
                return join(".",@ip);
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

=head2 check_if_tagged(port)


Check if port is a tagged trunk. Returns 1 if the port is tagged, 0 if
untagged.


=cut

sub check_if_tagged {
    my $snmp = shift;
    my $port = shift;

    my $oid = ".1.3.6.1.4.1.9.9.46.1.6.1.1.14.$port";

    my $res = $snmp->snmp->get_request ( $oid );
    return ($res->{$oid} == 1) ? 1 : 0;
}

1;
