# $Header: /tmp/netpass/NetPass/lib/NetPass.pm,v 1.16 2005/04/13 20:57:43 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


package NetPass;
use strict;
use Class::ParmList qw(simple_parms parse_parms);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use SNMP::Device;
use NetPass::DB;
use Carp;

my $VERSION = 1.0001;
my $RELEASE = 0.96;

=head1 NAME

NetPass - Routines for interacting with the NetPass system

=head1 SYNOPSIS

 use NetPass;
 $np = new NetPass(-debug => [0 | 1]);

 $np->movePort(switch, port, [good | bad]);
 $np->quarantinePort(switch, port);
 $np->unquarantinePort(switch, port);

 $err = $np->error

=head1 METHODS

=cut

sub DESTROY {
	my $self = shift;
	$self->{'db'}->DESTROY() if defined($self->{'db'});
}

sub xx_AUTOLOAD {
        no strict;
        return if($AUTOLOAD =~ /::DESTROY$/);
        if ($AUTOLOAD=~/(\w+)$/) {
                my $field = $1;
                *{$field} = sub {
                                my $self = shift;
                                @_ ? $self->{"_$field"} = shift
                                   : $self->{"_$field"};
                                };
                &$field(@_);
        } else {
                Carp::confess("Cannot figure out field name from '$AUTOLOAD'");
        }
}

=head2 new NetPass(-config =E<gt> file, -notReally =E<gt> [0|1], -quiet =E<gt> [0|1], -debug =E<gt> [0|1])

=over 

Constructor.

=over 

=item config

 Path to C<netpass.conf> file.

=item notReally

 Tell us what you are going to do, but don't really do it.

=item quiet

 Be less verbose in what you log.

=item debug

 Be more verbose in what you log.

=back

Returns

 NetPass object  on success
 "db failure"    failed to connect to db

=back

=cut

sub new {
    my ($class, $self) = (shift, {});

    my $parms = parse_parms({
			     -parms => \@_,
			     -legal => [qw(-debug -cstr -dbuser -dbpass -notReally -quiet)],
			     -defaults => {
					   -cstr      => '',
					   -dbuser    => '',
					   -dbpass    => '',
					   -notReally => 0,
					   -debug     => 0,
					   -quiet     => 0
					  }
			    }
			   );
    die Carp::longmess (Class::ParmList->error) if (!defined($parms));

    ($self->{'debug'},
     $self->{'cstr'},
     $self->{'dbuser'},
     $self->{'dbpass'},
     $self->{'notReally'},
     $self->{'quiet'}) = $parms->get('-debug', '-cstr', '-dbuser',
				     '-dbpass', '-notReally', '-quiet');

    $self->{'db'}  = new NetPass::DB($self->{'cstr'}, $self->{'dbuser'},
				     $self->{'dbpass'});

    return "db failure ".DBI->errstr if (!defined($self->{'db'}));

    $self->{'cfg'} = new NetPass::Config($self->{'db'},
					 $self->{'debug'});

    return bless $self, $class;
}

sub db {
	my $self = shift;
	return $self->{'db'};
}

sub D {
    my $self = shift;
    return (defined($self->{'debug'}) && $self->{'debug'}) ? 1 : 0;
}

sub Q {
    my $self = shift;
    return (defined($self->{'quiet'}) && $self->{'quiet'}) ? 1 : 0;
}

=head2 $np-E<gt>error()

=over 

 Tell us what's gone wrong.

=back

=cut

sub error {
    my $self = shift;
    my $text = shift;
    return $self->{'error'} unless defined($text);
    $self->{'error'} = $text;
}

=head2 $np-E<gt>cfg()

=over

 Return the NetPass::Config object so you can more easily call NetPass::Config
 methods. E.g. $np->cfg->something()

=back

=cut

sub cfg {
    my $self = shift;
    return $self->{'cfg'};
}


=head2 $val = $np-E<gt>policy($key, $network)

=over

Given a key (a policy/configuration variable name) return the associated value
or undef if the variable doesnt exist in the C<netpass.conf> file's 
E<lt>policyE<gt> section. If the network is given, we'll search there first.
If the key doesn't exist on the specified network, we'll search the global
policy.

=back

=cut

sub policy {

	die Carp::longmess("DEPRECATED. FIX ME.");

    my $self = shift;
    my $pvar = shift;

    return $self->{'cfg'}->policy($pvar);
}

=head2 movePort(-switch =E<gt> switch, -port =E<gt> port, -vlan =E<gt> E<lt>unquarantine | quaranineE<gt>)

Move a port to its unquarantined or quarantined VLAN as appropriate
for the given switch (i.e. as defined in C<netpass.conf>). Returns 1 on success, 
0 on failure. Check np-E<gt>error for reason.

=cut

sub movePort {
    my $self = shift;
    my ($hn, $port, $vlan) = simple_parms([qw(-switch -port -vlan)], @_);

    my $cfg = $self->{'cfg'};

    if ($vlan !~ /^(unquarantine|quarantine)$/i) {
	$self->error(qq{vlan param must be either "quarantine" or "unquarantine"});
	return 0;
    }

    $self->error("");

    # lookup what VLANs are available on this switch/port.
    # complain if we're being asked to put the port into an unavailable
    # VLAN

    # [0] = unquarantine, [1] = quaratine
    my @av = $cfg->availableVlans(-switch => $hn, -port => $port);

    $vlan =~ tr [A-Z] [a-z];

    my $_vlan = $av[ $vlan eq "unquarantine" ? 0 : 1 ];

    if ( ! $self->cfg->isVlanAvailable($hn, $port, $_vlan) ) {

	if (!defined($_vlan)) {
	    $self->error("$hn port $port is UNMANAGED\n");
	} else {
	    my $e = "VLAN $_vlan (i.e. \"$vlan\") is not available on $hn port $port.\n\
Available tags are:\n";
	    if(!defined($av[0])) {
		$e .= "no available vlans on this port! (port not listed in netpass.conf?)\n";
	    } else {
		$e .= join(" and ", @av);
	    }
	    $self->error($e);
	}
	return 0;
    }
    
    # set the port to the specified vlan
    
    my ($r, $w) = $cfg->getCommunities($hn);
    my $dev     = new SNMP::Device('hostname'       => $hn, 
				   'snmp_community' => $w, 
				   'debug'         => $self->{'debug'});

    if ( defined($dev->err) ) {
	_log ("ERROR", "new SNMP::Device failed: ".$dev->err."\n");
	$self->error("new SNMP failed ".$dev->err);
	return 0;
    }

    my $x       = $dev->get_vlan_membership($port);
    
    if (!defined($x)) {
	_log ("ERROR", "failed to retrieve vlan membership for $hn/$port ".$dev->err."\n");
	$self->error("failed to retrieve vlan membership for $hn/$port ".$dev->err);
	return 0;
    }

    _log ("DEBUG", "$port is currently in vlans: ", join(',', @$x), "\n")
      if $self->D;

    if (grep (/^$_vlan$/, @$x)) {
	    _log ("WARNING", "$hn/$port is already in vlan $vlan ($_vlan)\n");
	    $self->error("already in that vlan: nothing to do!");
	    return 1; # success
    }

    _log ("INFO", "Setting port $port on $hn to PVID $_vlan ($vlan)\n")
      if !$self->Q;

    # get the default vlan ID in case we need to backout

    my $default_vlan_id = $dev->get_default_vlan_id($port);

    if ( !defined($default_vlan_id) ) {
	_log ("ERROR", "Failed to fetch default_vlan_id for $hn/$port error: ".$dev->err."\n");
	$self->error("Failed to fetch default_vlan_id for $hn/$port error: ".$dev->err);
	return 0;
    }
    
    # set the default vlan for untagged packets (nortel speak: "PVID")

    if( $dev->set_default_vlan_id($port, $_vlan) == 0 ) {
	$self->error("failed to set_default_vlan_id $hn/$port to $_vlan : " . $dev->err);
	_log ("ERROR", "Failed to set default vlan $hn/$port to $_vlan error: ".$dev->err."\n") if !$self->Q;
	return 0;
    }

    _log ("INFO", "succeeded in setting default vlan id $hn/$port $_vlan.\n")
      if !$self->Q;

    # find out what vlan's we're already members of and, for sanity's
    # sake, remove us from all of them. however, in the netpass
    # environment, @$x should always only contain a single vlan.
								     
    foreach my $curVlan (@$x) {
	_log("INFO", "Removing port $port from VLAN $curVlan ..\n")
	  if !$self->Q;
	if ( !$dev->del_vlan_membership($port, $curVlan) ) {
	    $self->error("failed to remove $port from vlan $curVlan : ".$dev->err);
	    _log("ERROR", "failed to remove $port from vlan $curVlan : ".$dev->err)
	      if !$self->Q;
	    _log("INFO", "setting default vlan for $hn/$port back to $default_vlan_id\n");
	    if (!defined($dev->set_default_vlan_id($port, $default_vlan_id))) {
		_log ("ERROR", "backout failed to set default vlan $hn/$port $default_vlan_id\n");
	    }
	    return 0;
	}
    }

    # set the vlan membership
    # bad = av[1], good = $av[0]
    
    _log("INFO", "adding $hn/$port to vlan $_vlan ..\n") if !$self->Q;

    if ( !$dev->add_vlan_membership($port, $_vlan) ) {
	_log("ERROR", "add_vlan_membership $hn/$port $_vlan failed ".$dev->err."\n") if !$self->Q;
	$self->error("failed to add $hn/$port to vlan $_vlan : ".$dev->err);
	_log("INFO", "backingout changes $hn/$port def=$default_vlan_id vlan=",
	     join(',', @$x), "\n");
	if (!defined($dev->set_default_vlan_id($port, $default_vlan_id))) {
	    _log("ERROR", "backout failed to set default vlan id $hn/$port $default_vlan_id\n");
	}

	foreach my $curVlan (@$x) {
	    _log ("INFO", "backingout $hn/$port to $curVlan\n");
	    if ( !$dev->add_vlan_membership($port, $curVlan) ) {
		_log("ERROR", "backout failed to add $hn/$port to $curVlan\n");
		# we'll keep going if there are other vlans in $x
		# so if someone needs to manually reset the port, there's
		# less to do (hopefully)
	    }
	}

	return 0;
    }

    _log("INFO", "succeeded.\n") if !$self->Q;

    return 1;

}

=head2 $bool = authenticateUser($username, $password)

Based on the AUTH_METHOD setting in C<netpass.conf> authenticate the username 
and password.

=cut

sub authenticateUser {
    my $self = shift;
    my ($u, $p) = (shift, shift);

    no strict 'refs';

    my $auth_mod = $self->{'cfg'}->policy('AUTH_METHOD');
    _log "DEBUG", "auth_meth = $auth_mod\n";

    if (exists $self->{'auth_mod_loaded'}) {
	my $auth_r = $auth_mod."::authenticateUser";
	_log "DEBUG", "calling $auth_r with username=$u password=[suppressed]\n";
	return &$auth_r($self, $u, $p);
    } else {
	_log "DEBUG", "loading $auth_mod\n";
	eval "require $auth_mod";
	if ($@) {
	    _log "ERROR", "failed to load $auth_mod <$@>\n";
	    return 0;
	} else {
	    $self->{'auth_mod_loaded'} = 1;
	    _log "DEBUG", "$auth_mod loaded\n";
	    my $auth_r = $auth_mod."::authenticateUser";
	    _log "DEBUG", "calling $auth_r with username=$u password=[suppressed]\n";
	    return &$auth_r($self, $u, $p);
	}
    }
    return 0;
}

=head2 $bool = authenticateAdmin($username, $password)

Based on the ADMIN_AUTH_METHOD setting in C<netpass.conf> authenticate the username 
and password.

=cut

sub authenticateAdmin {
    my $self = shift;
    my ($u, $p) = (shift, shift);

    no strict 'refs';

    my $auth_mod = $self->{'cfg'}->policy('ADMIN_AUTH_METHOD');
    _log "DEBUG", "admin_auth_meth = $auth_mod\n";

    if (exists $self->{'auth_mod_loaded'}) {
	my $auth_r = $auth_mod."::authenticateUser";
	_log "DEBUG", "calling $auth_r with username=$u password=[suppressed]\n";
	return &$auth_r($self, $u, $p);
    } else {
	_log "DEBUG", "loading $auth_mod\n";
	eval "require $auth_mod";
	if ($@) {
	    _log "ERROR", "failed to load $auth_mod <$@>\n";
	    return 0;
	} else {
	    $self->{'auth_mod_loaded'} = 1;
	    _log "DEBUG", "$auth_mod loaded\n";
	    my $auth_r = $auth_mod."::authenticateUser";
	    _log "DEBUG", "calling $auth_r with username=$u password=[suppressed]\n";
	    return &$auth_r($self, $u, $p);
	}
    }
    return 0;
}

=head2 $np->enforceMultiMacPolicy($mac, $ip, $sw, $po, $mp, $pm)

Given a ton of cra^H^H^Hparameters, enforce the configured MULTI_MAC policy 
setting. Possible settings are:

=over 4

=item MULTI_MAC_ALL_OK

if we are listed on the port and there are
other clients, make sure all of them are OK before
activating the port

else, port is quarantined and OK clients get
a special message letting them know why they
have been quarantined

=item MULTI_MAC_ONE_OK

the port may contain multiple macs, only one of
them must be registered to activate the port

=item MULTI_MAC_DISALLOWED

multiple macs on a port is not permitted. the
port is quarantined if multiple macs are seen

=back

=cut

sub enforceMultiMacPolicy {
	my ($self, $mac, $ip, $status, $sw, $po, $mp, $pm) = @_;

	if ( $self->policy('MULTI_MAC') eq "ALL_OK" ) {
		_log "DEBUG", "$mac $ip MULTI_MAC policy is ALL_OK $sw/$po\n";
		my $allOK = 1;
		my @OKmacs;

		# if we are P/QUAR and policy is ALL_OK then cut to the chase

		return ($status, $sw, $po) if ($status =~ /^[P]QUAR/);

		foreach my $m (@{$pm->{$po}}) {
			#_log("DEBUG", "$m eq $mac?\n");
			next if $m eq $mac; # it's us
			my $neighbor_status = $self->db->macStatus($m);
			if ( !defined($neighbor_status) || ($neighbor_status ne "UNQUAR") ) {
				_log "DEBUG", "$mac $ip found an unreg/quar neighbor $m status=".(defined($neighbor_status)?$neighbor_status:"UNREG")."\n";
				$self->db->audit(-mac => $mac, -ip => $ip, 
					       -msg => [ "multi-mac: BAD neighbor $m status ".
							 (defined($neighbor_status)?$neighbor_status:"UNREG") ]);
				$allOK = 0;
			} else {
				$self->db->audit(-mac => $mac, -ip => $ip, 
					       -msg => [ "multi-mac: OK neighbor $m status ".
							 (defined($neighbor_status)?$neighbor_status:"UNREG") ]);
				push @OKmacs, $m;
			}
		}
		
		# no: leave port quar, set our message to msg:multi_mac
		
		if (!$allOK) {
			_log "DEBUG", "$mac $ip on $sw $po at least one of our neighbors is unreg/quar. setting message to msg:multi_mac\n";
			
			$self->db->audit(-mac => $mac, -ip => $ip, 
				       -msg => [ "multi-mac: at least one neighbor is BAD. we will receive msg:multi_mac" ]);
			
			$self->db->setMessage($mac, 'msg:multi_mac');
			
			# we return permQuar because there's really no way for
			# them to unquarantine themselves - there's no remediation
			# steps, results, etc.
			return ("PQUAR", $sw, $po);
		}
		
		# yes: movePort
		
		$self->db->audit(-mac => $mac, -ip => $ip, 
				-msg => [ "multi-mac: all of our neighbors are OK." ]);
		
		return ($status, $sw, $po);
	}
	
	# XXX the other MULTI_MAC policies are:
	# XXX ELSE ONE_OK
	# XXX ELSE DISALLOWED
	# XXX for future implementation
	
	_log "ERROR", "MULTI_MAC policy ".$self->policy('MULTI_MAC')." not implemented\n";
	return ($status, $sw, $po);
}

=head2 ($sw, $po, $mac2portHashRef, $port2macHashRef) = $np->findOurSwitchPort($ourMac, $ourIP)

Given a mac address and IP address, try to figure out which switch/port it is on. If
PORT_SEARCH_ALGO is set to TREE then we (via the SNMP modules) will attempt to do
a more intelligent search, starting at the BSW and working down by using the
topology MIB. If BSW is not set, we will fall back to a linear search. Linear
searching, depending on the number of switches in the network, can be _extremely_
slow.

=cut

sub findOurSwitchPort {
	my ($self, @args) = (shift, @_);
	
	if ($self->cfg->policy('PORT_SEARCH_ALGO') eq "TREE") {
		my @rvs = $self->findOurSwitchPort_tree(@args); 
		# if we succeeded, return, else fall thru to linear
		return @rvs if defined($rvs[0]);
	}
	return $self->findOurSwitchPort_linear(@args); 
}

=head2 B<($ip, $ifIndex, $mp, $pm) = search_topology($switch, $commname, $mac)>

 Starting with the current switch, recursively search for given mac
 address, jumping to other switches when necessary. 

=cut

sub search_topology {
	my $self      = shift;
	my $switch    = shift;
	my $community = shift;
	my $mac       = shift;
	my $loopctl   = shift;

	# first determine which port this mac address is on. if we dont find the 
	# mac on this switch - stop.

	if (exists $loopctl->{$switch}) {
		_log("ERROR", "$mac search_topo detected a loop. we've already searched $switch\n");
		return (undef, undef, undef, undef);
	}

	$loopctl->{$switch} = 1;

	my $snmp = new SNMP::Device('hostname'       => $switch,
				    'snmp_community' => $community,
				    'debug' => 0);

	if (!defined($snmp)) {
		_log("ERROR", "$mac failed to create SNMP::Device for ".$self->ip."\n");
		return (undef, undef, undef, undef);
	}

	my $ifIndex = $snmp->get_mac_port($mac); 
	return (undef, undef, undef, undef) if !defined($ifIndex); # not on this switch

	_log ("DEBUG", "$mac possibly found on $switch / $ifIndex. checking to see if it links to another switch.\n");
	
	# now, examine the port that the mac is on and determine if 
	# it connects to another switch or not. if it doesnt, we've found
	# the end user's port. if it does connect to another switch, 
	# move to that switch and repeat this search.
	
	my $next_switch = $snmp->get_next_switch($ifIndex);
	if (defined($next_switch) && ($next_switch ne "")) {
		_log("DEBUG", "$mac it's another switch ($next_switch). searching that one.\n");

                if($next_switch !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
                        _log ("DEBUG", "$mac next_switch is $next_switch which doesnt look like an IP\n");
                        return (undef, undef, undef, undef);
                }

		return $self->search_topology($next_switch,
					      ($self->cfg->getCommunities($next_switch))[1],
					      $mac, $loopctl);
	}

	# otherwise, it's this switch. to preserve the semantics
	# of the linear version of this search, we'll return
	# the mac-to-port mappings.

	_log("DEBUG", "$mac it's not another switch. so this is likely our sw/port: $switch/$ifIndex\n");

	my ($mp, $pm) = $snmp->get_mac_port_table();
	return ($switch, $ifIndex, $mp, $pm);
}

sub findOurSwitchPort_tree {
	my ($self, $mac, $ip) = (shift, shift, shift);
	
	# the switch/snmp module returns zero-padded macs. we need to pad
	# our's out so that the hash lookup works.
	
	$mac = padMac($mac);
	
	_log ("DEBUG", "finding network for $ip\n");
	my $myNW = $self->cfg->getMatchingNetwork(-ip => $ip);
	
	# this is a total lame work around for what looks like a nortel
	# bug. very occasionally it will return the mac on the wrong port (the uplink)
	# so we'll retry just once to see if the switch will tell us the right
	# thing. otherwise we'll do a linear search. doing the tree search
	# twice will still be better than punting and going to linear.

	for (my $try = 0 ; $try < 2 ; $try++) {
		_log("DEBUG", "$mac $ip try $try/1\n");
		if (defined($myNW)) {

			# sometimes you might have multiple roots connected with
			# devices that cant share topology information. we get around
			# this by allowing you to specify multiple BSWs. the hope is
			# that 2-3 tree searches might still be more efficient than
			# a single linear search.

			my $bsw_list = $self->cfg->getBSW($myNW);
			if (!defined($bsw_list)) {
				_log ("WARNING", "$mac attempted to use tree-search on $myNW,  but no BSW defined. fallback to linear.\n");
				return $self->findOurSwitchPort_linear($mac, $ip);
			}

			foreach my $bsw (split(' ', $bsw_list)) {
				_log ("DEBUG", "$mac starting point bsw=$bsw\n");
				
				my ($_sw, $_po, $_mp, $_pm) = $self->search_topology($bsw, 
										     ($self->cfg->getCommunities($bsw))[1],
										     $mac, {});
				
				next if (!defined($_sw) || !defined($_po));

				_log("DEBUG", "$mac $ip search_topo thinks we're on $_sw/$_po. intersecting sets to be sure\n");
				my $portList = $self->cfg->configuredPorts($_sw);
				
				_log("DEBUG",  "$mac $ip possible port=$_po\n");
#				_log("DEBUG",  "$mac $ip portList=",Dumper($portList),"\n");
				use Set::Scalar;
				my $set1 = new Set::Scalar($_po);
				my $set2 = new Set::Scalar(@$portList);
				my $intersection = $set1->intersection($set2);
				my $first_member = ($intersection->members)[0];
				if($intersection->size > 1) {
					_log "WARNING", "$mac $ip found us on multiple ports on $_sw ports=".join(',', $intersection->members)." - we will return the first port only\n";
					return ($_sw, $first_member, $_mp, $_pm);
				} elsif($intersection->size == 1) {
					_log "DEBUG", "$mac $ip found us on $_sw/$first_member\n";
					return ($_sw, $first_member, $_mp, $_pm);
				}
				_log("WARNING", "$mac $ip try=$try intersection of sets is null sw=$_sw po=$_po. we'll try one more time.\n");
			}
			
		} else {
			_log ("ERROR", "$mac $ip unknown ip (no configured network)\n");
			$try = 3;
		}

	}
	
	_log ("DEBUG", "$mac $ip could not find us on the network!\n");
	return (undef, undef, undef, undef);
}

sub findOurSwitchPort_linear {
	my ($self, $mac, $ip) = (shift, shift, shift);
	
	# the switch/snmp module returns zero-padded macs. we need to pad
	# our's out so that the hash lookup works.
	
	$mac = padMac($mac);
	
	_log "DEBUG", "finding network for $ip\n";
	my $myNW = $self->cfg->getMatchingNetwork(-ip => $ip);
	
	if (defined($myNW)) {
		my $switches = $self->cfg->getSwitches($myNW);
		
		_log "DEBUG", "$mac $ip nw is $myNW ".($#{$switches}+1)." switches on this network\n";
		
		foreach my $nsw (@{$self->cfg->getSwitches($myNW)}) {
			_log "DEBUG", "$mac $ip search $nsw for us\n";
			
			my $snmp = new SNMP::Device('hostname'       => $nsw,
						    'snmp_community' =>
						    ($self->cfg->getCommunities($nsw))[1]);
			
			if ( defined($snmp->err) ) {
				_log ("ERROR", "new SNMP::Device failed: ".$snmp->err."\n");	
				return (undef, undef, undef, undef);
			}
			
			my ($mp, $pm) = $snmp->get_mac_port_table();
			
			_log ("ERROR", "get_mac_port_table returned undef! ".$snmp->err."\n")
			  if (!defined($mp) || !defined($pm));
			
			# XXX we need to exclude unmanaged ports. e.g. 
			# if we are seen on an uplink port of another switch (likely)
			# then we dont want to return that as our official port. 
			# the uplink of the other sw wont be managed (wont be in 
			# netpass.conf) so we can exclude on that. we should only appear
			# on one managed port, so we'll return the first one.
			
			use Data::Dumper;
			#	    print STDERR "we are $mac\nmac-port-table is: ", Dumper($mp), "\n";
			if (exists $mp->{$mac}) {
				# yes, we're on this switch
				_log "DEBUG", "$mac $ip possibly found us on $nsw/".join(',', @{$mp->{$mac}})."\n";
				
                                my $portList = $self->cfg->configuredPorts($nsw);

                                #print STDERR "macport ", Dumper($mp->{$mac}), "\n";
                                #print STDERR "portList=",Dumper($portList),"\n";
                                use Set::Scalar;
                                my $set1 = new Set::Scalar(@{$mp->{$mac}});
                                my $set2 = new Set::Scalar(@$portList);
                                my $intersection = $set1->intersection($set2);
                                my $first_member = ($intersection->members)[0];
                                if($intersection->size > 1) {
                                        _log "WARNING", "$mac $ip found us on multiple ports on $nsw ports=".join(',', $intersection->members)." - we will return the first port only\n";
                                        return ($nsw, $first_member, $mp, $pm);
                                } elsif($intersection->size == 1) {
                                        _log "DEBUG", "$mac $ip found us on $nsw/$first_member\n";
                                        return ($nsw, $first_member, $mp, $pm);
				}
			}
		}
	} else {
		_log "ERROR", "$mac $ip unknown ip (no configured network) $ip\n";
	}
	
	_log "DEBUG", "$mac $ip could not find us on the network!\n";
	return (undef, undef, undef, undef);
}




=head2 ($rv, $sw, $po) = $np->validateMac($mac, $ip)

Run validation checks on the client. Basically:

 has the mac previously been through netpass?
 no:
        return UNREG
 yes:
        are they flagged as quarantined? (ie. manually, by
        the future IDS feature, because they have unresolved
        issues, etc)
        no:
                is there anyone else on their port?
                no:
                        return UNQUAR
                yes:
                        are any of those macs flagged as quarantined?
                        no:
                                return UNQUAR
                        yes:
                                return PQUAR
        yes:
                return QUAR

Returns a status of "UNREG", "QUAR", "PQUAR", "UNQUAR", "PUNQUAR"
on success as well as the switch and port that the client is on. 
If the switch and port can't be determined, they will be returned
as C<undef>.

=cut


sub validateMac {
    my ($self, $mac, $ip) = (shift, shift, shift);

    if (!defined($mac) && !defined($ip)) {
	_log "ERROR", "mac and ip are both required params\n";
    }

    my $status = $self->db->macStatus($mac);
    if ( defined($status) ) {

	_log "DEBUG", "$mac $ip is registered\n";

	# activate the clients port:
	# 1. determine switch/port via database
	# 2. if that switch/port is not in the vlan map -> long method
	# 3. examine mac attached to switch port. (we do this to keep
	#    the move process as short as possible for registered/OK clients)
	# 4. if we are listed on the port, activate the port
	# 5. else (slow method) lookup list of switches
	#    that service our network
	# 6. search each switch for our mac
	# 7. turn on the port we are attached too

	my ($sw, $po) = $self->db->lookupSwitchPort($mac);

	if (!defined($sw) || !defined($po)) {
		_log ("DEBUG", "$mac $ip no sw/po in database. searching for them\n");
		goto long_way;
	}

	my $managedPorts = $self->cfg->configuredPorts($sw);
	if (ref($managedPorts) ne "ARRAY") {
		_log ("DEBUG", "configuredPorts($sw) didnt return an array ref\n");
		goto long_way;
	}

	goto long_way if (!grep (/^$po$/, @$managedPorts));

	$self->cfg->debug(1);

	my $snmp = new SNMP::Device('hostname'  => $sw,
				    'snmp_community'  =>
				    ($self->cfg->getCommunities($sw))[1]);

	$self->cfg->debug(0);


	if ( defined($snmp->err) ) {
		_log ("ERROR", "new SNMP::Device failed: ".$snmp->err."\n");
		return ("UNREG", undef, undef);
	}
	
	#_log ("DEBUG", "SNMP::Device log = ". $snmp->log . "\n");
	
	# fetch the mac<->port mappings
	
	my ($mp, $pm) = $snmp->get_mac_port_table();

	#_log("DEBUG", "$mac $ip porttable=", Dumper($pm), "\n");

	if (grep (/^$mac$/, @{$pm->{$po}})) {

	    # yes, we're on the expected port

	    _log("DEBUG", "$mac $ip is on the expected $sw/$po maccount=".($#{$pm->{$po}}+1)."\n");

	    $self->db->audit(-mac => $mac, -ip => $ip, 
			-msg => [ "validate: found us on $sw port $po (short method)" ]);

	    if( $#{$pm->{$po}} == 0 ) {

		# and we're alone

		$self->db->audit(-mac => $mac, -ip => $ip, 
			    -msg => [ "validate: we are alone on $sw port $po" ]);

		_log("DEBUG", "$mac $ip is alone. returning a status of $status\n");

		return ($status, $sw, $po);

	    } else {

		$self->db->audit(-mac => $mac, -ip => $ip, 
			    -msg => [ "validate: we are NOT alone on $sw port $po" ]);

		_log("DEBUG", "$mac $ip we're not alone on $sw/$po.\n");

		# else, we're not alone on this port. enforce the
		# appropriate MULTI_MAC policy

		return $self->enforceMultiMacPolicy($mac, $ip, $status,
						    $sw, $po, $mp, $pm);
	    }
	} else {

	  long_way:

	    # we're not on the expected port, so we need to do it
	    # the hard way.. find out which port we're on
	    # fetch switch list based on our ip/network

	    _log("DEBUG", "$mac $ip not on expected sw/po $sw/$po. searching..\n");

	    ($sw, $po, $mp, $pm) = $self->findOurSwitchPort($mac, $ip);

	    if( defined($sw) && defined($po) ) {

		# update the database so in the future we, hopefully,
		# dont have to do this iterative search
		
		$self->db->setSwitchPort($mac, $sw, $po);

		$self->db->audit(-mac => $mac, -ip => $ip, 
			    -msg => [ "validate: found us on $sw port $po (long method)" ]);

		if( $#{$pm->{ $mp->{$mac} }} == 0) {
		    # and we're alone
		    $self->db->audit(-mac => $mac, -ip => $ip, 
				-msg => [ "validate: we are alone on $sw port $po" ]);
		    _log "DEBUG", "$mac $ip and we're alone. returning status of $status\n";
		    return ($status, $sw, $po);
		} else {
		    $self->db->audit(-mac => $mac, -ip => $ip, 
				-msg => [ "validate: we are NOT alone on $sw port $po" ]);

		    _log "DEBUG", "$mac $ip we're not alone.\n";
		    
		    # else, we're not alone on this port. enforce the 
		    # appropriate MULTI_MAC policy
		    
		    return $self->enforceMultiMacPolicy($mac, $ip, $status,
						      $sw, $po, $mp, $pm);
		}
	    } else {
		# we couldnt find them. 
		# this most likely means they are a remote client
		# on a switch/network that isnt part of the quar/unquar
		# environment (e.g. a home user, dialup user, etc)
		
		return ("UNREG", undef, undef);
	    }
	}

    } # else macStatus == UNDEF -> unregistered

    # we need to determine the switch and port that this new client is on

    my ($sw, $po) = $self->findOurSwitchPort($mac, $ip);

    if (!defined($sw) || !defined($po)) {
	# we couldnt find them. 
	# this most likely means they are a remote client
	# on a switch/network that isnt part of the quar/unquar
	# environment (e.g. a home user, dialup user, etc)
	
	_log "WARNING", "$mac $ip couldnt find us on any switch\n";
    }

    return ("UNREG", $sw, $po);
}

sub padMac {
        my $m = shift;
	return $m unless defined($m);
        $m = "0" x (12-length($m)) . $m;
	$m =~ tr [A-Z] [a-z];
	return $m;
}



=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: NetPass.pm,v 1.16 2005/04/13 20:57:43 jeffmurphy Exp $

=cut

1;
