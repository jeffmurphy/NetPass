package NetPass::API;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use Digest::MD5 qw(md5_hex);
use Class::ParmList qw(simple_parms parse_parms);

=head1 NAME

NetPass::API - NetPass API

=head1 SYNOPSIS

    use NetPass::API;

=head1 DESCRIPTION

This is the NetPass::API object which provides access to the
NetPass object throught SOAP. This package should only
be used in conjunction with npapid.pl daemon.

=head1 METHODS

=cut

my $check_soap_auth = sub {
        my $self         = shift;
        my $their_secret = shift;
        my $rip          = $::remote_ip;
        my $np           = $::np;

        my $secret       = $np->cfg->npapiSecret();
        my $my_secret    = md5_hex($rip.$secret);

        return ($their_secret eq $my_secret) ? 1 : 0;
};

my $get_secret_from_args = sub {
        my $self = shift;
        my @args = @_;
        my $secret;

        if (ref($args[0]) eq 'HASH') {
                return undef if ($#args > 0 || !exists $args[0]->{'-secret'});
                $secret = $args[0]->{'-secret'};
                delete $args[0]->{'-secret'};
        } else {
                my $i;
                my $j;
                for ($i = 0; $i <= $#args; $i++) {
                        last if ($args[$i] eq '-secret');
                }
                ($j, $secret) = splice(@args, $i, 2);
        }

        return ($secret, \@args);
};

my $execute_user_defined_function = sub {
	my $self     = shift;
	my $function = shift;
	my @args     = @_;

	eval { require NetPass::API::Local; };

	if ($@) {
		#_log("DEBUG", "NetPass::API::Local does not exist or has an error in it ".$@);
		return 0;	
	}

	my $e  = \&{"NetPass::API::Local::$function"};
	my $rv = eval { &$e(@args); }; 

	if ($@) {
		_log("DEBUG", "$e does not exist or has an error in it ".$@);
		return 0;
	}

	return $rv;
};

=head2 $rule = getSnortPCAPFilter(-secret => $secret, -sensor => $hostname -ignorequar => [1|0])

Get the necessary pcap rules for the particular sensor. Argument 
-ignorequar will append the necessary vlan rules to exclude quarantine
vlans if true. Returns a string of the rule on success, C<undef> on failure.

=cut

sub getSnortPCAPFilter {
	my $self    = shift;
	my $np      = $::np;
	my $nws     = ();
	my @pcap;

        my $parms = parse_parms({
                                  -parms    => \@_,
                                  -legal    => [ qw(-secret -sensor -ignorequar) ],
				  -required => [ qw(-secret -sensor) ],
                                  -defaults => { -secret  => '',
                                                 -sensor  => '',
						 -ignorequar => 0,
                                               }
                                });

	return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
	my ($secret, $sensor, $ignorequar) = $parms->get('-secret', '-sensor', '-ignorequar');

	return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("getSnortPCAPFilter", @_) < 0;

        if ($sensor !~ /^\w*\.*\w*\.*\w+\.\w+:\d+$/) {
                _log("ERROR", "Incorrect sensor format $sensor");
                return undef;
        }

        $nws = $np->cfg->getNetworks();
        if (!defined($nws) || ref($nws) ne 'ARRAY') {
                _log("ERROR", "Unable to retrieve list of networks");
                return undef;
        }

        foreach my $net (@$nws) {
                next unless $np->cfg->snortEnabled($net) =~ /^(enabled|not_really)$/;
                my $nets = $np->cfg->getSnortSensors($net);
                next unless defined $nets && ref($nets) eq 'HASH';

		if (exists $nets->{$sensor}) {
			my $r = "(";
			if ($ignorequar) {
				my $qvlan = $np->cfg->quarantineVlan($net);
				$r .= "not vlan $qvlan and" if $qvlan =~ /^\d+$/;
			}

			$r .= " src net $net)";
			push  @pcap, $r;
		}
        }

	return join(' or ', @pcap);
}

=head2 $aref = getSnortRules(-secret => $secret, -type => $type = <enabled | disabled | all>)
			     

Retrieve snort rules registered in the NetPass database. Arguments include
a secret, type either return all enabled rules, all disabled rules, or all
rules. Returns an C<array reference> on success, C<undef> on failure.

=cut

sub getSnortRules {
	my $self   = shift;
	my $np	   = $::np;
	my @aref;

        my $parms = parse_parms({
                                  -parms    => \@_,
                                  -legal    => [ qw(-secret -type) ],
				  -required => [ qw(-secret -type) ],
                                  -defaults => { -secret  => '',
                                                 -type    => '',
                                               }
                                });

        return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
        my ($secret, $type) = $parms->get('-secret', '-type');

	return undef unless ($self->$check_soap_auth($secret));
	return undef unless ($type =~ /^(enabled|disabled|all)$/);
	return undef if $self->$execute_user_defined_function("getSnortRules", @_) < 0;

	_log("DEBUG", "retrieving snort rules");

	my $rules = $np->db->getSnortRules($type);
	_log("ERROR", "Unable to retrieve rules from database")
	  	     unless defined($rules);
	return undef unless defined($rules);

	push @aref, @$rules;
	return \@aref;
}

=head2 getResults(-secret => $secret, ...)

  Refer to Netpass::DB for documentation.

=cut


sub getResults {
	my $self = shift;
        my $np   = $::np;

	my($secret, $args) = $self->$get_secret_from_args(@_);
	return undef if $secret eq "";
        return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("getResults", @_) < 0;

	return $np->db->getResults(@$args);
}

=head2 addResult(-secret => $secret, ...)

  Refer to NetPass::DB for documentation.

=cut

sub addResult {
	my $self = shift;
        my $np   = $::np;

	my($secret, $args) = $self->$get_secret_from_args(@_);
	return undef if $secret eq "";
        return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("addResult", @_) < 0;

	return $np->db->addResult(@$args);
}

=head2 updateResult(-secret => $secret, ...)

  Refer to NetPass::DB for documentation.

=cut

sub updateResult {
        my $self = shift;
        my $np   = $::np;

        my($secret, $args) = $self->$get_secret_from_args(@_);
        return undef if $secret eq "";
        return undef unless ($self->$check_soap_auth($secret));
        return undef if $self->$execute_user_defined_function("updateResult", @_) < 0;

        return $np->db->updateResult(@$args);
}


=head2 my $bool = snortEnabled($secret, $network)

Determines snort status on the specified network, returns either
enabled, disabled, or not_really on success, undef on failure.

=cut

sub snortEnabled {
	my $self   = shift;
	my $secret = shift;
	my $nw     = shift;
	my $np	   = $::np;

	return undef unless ($self->$check_soap_auth($secret));
	return undef unless defined $nw;
	return undef if $self->$execute_user_defined_function("snortEnabled", @_) < 0;

	return $np->cfg->snortEnabled($nw);
}

=head2 my $networks = snortEnabledNetworks($secret, $sensor)

Get all the networks snort is enabled on. If $sensor is defined
as hostname:port of a configured snort sensor all the networks
that particular sensor is enabled on is returned as an  ARRAY 
ref. Returns an ARRAY ref of all the snort enabled networks on
success, C<undef> on failure.

=cut

sub snortEnabledNetworks {
        my $self   = shift;
        my $secret = shift;
	my $sensor = shift;
        my $np     = $::np;

	my $nws    = ();
	my @snortnws;

        return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("snortEnabledNetworks", @_) < 0;
	$nws = $np->cfg->getNetworks();

	if (!defined($nws) || ref($nws) ne 'ARRAY') {
		_log("ERROR", "Unable to retrieve list of networks");
		return undef;
	}

	if ($sensor !~ /^\w*\.*\w*\.*\w+\.\w+:\d+$/) {
		_log("ERROR", "Incorrect sensor format $sensor");
		return undef;
	}

	foreach my $net (@$nws) {
		next unless $np->cfg->snortEnabled($net) =~ /^(enabled|not_really)$/;
		my $nets = $np->cfg->getSnortSensors($net);
		next unless defined $nets && ref($nets) eq 'HASH';
		next unless exists $nets->{$sensor};
		push @snortnws, $net;
	}

        return \@snortnws;
}

=head2 $rv = getRegisterInfo(-secret => secret, ...)

Refer to NetPass::DB::getRegisterInfo for documentation.

=cut

sub getRegisterInfo {
	my $self = shift;
        my $np   = $::np;

	my($secret, $args) = $self->$get_secret_from_args(@_);
	return undef if $secret eq "";
        return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("getRegisterInfo", @_) < 0;

	return $np->db->getRegisterInfo(@$args);
}

=head2 $msg = getPage(-secret => $secret, ...)

 Refer to NetPass::DB::getPage for documentation.

=cut

sub getPage {
        my $self = shift;
        my $np   = $::np;
        
	my($secret, $args) = $self->$get_secret_from_args(@_);
	return undef if $secret eq "";
	return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("getPage", @_) < 0;
        
	return $np->db->getPage(@$args);
}

=head2 $rv = addSnortRuleEntry(-secret => $secret -rule => $rule -user => $user -desc => $desc)

This routine is basically a NetPass::API wrapper to NetPass::DB::addSnortRuleEntry,
for information regarding arguments see NetPass::DB::addSnortRuleEntry.

=cut

sub addSnortRuleEntry {
	my $self = shift;
	my $np   = $::np;

	my($secret, $args) = $self->$get_secret_from_args(@_);
	return undef if $secret eq "";
	return undef unless ($self->$check_soap_auth($secret));
	return undef if $self->$execute_user_defined_function("addSnortRuleEntry", @_) < 0;

	return $np->db->addSnortRuleEntry(@$args);
}

=head2 my $results = quarantineByIP(-secret => $secret, -ip => $ip, -id => $id, -type => $type, -time => $time, -aqo => [0 | 1])

Arguments to this function include a secret key, IP address to be
quarantined, an ID associated to either a Nessus or Snort ID,
a type corresponding to what exactly quarantined this IP, and a timestamp
when the incident occured. The type, ID, and time variables can also be
ARRAY references for multiple id's with their corresponding types and
timestamps, however there must be an equal number of elements in each
of the arrays or an error will occur. 

The aqo ("autoquaroverride") parameter allows you to quarantine a host even
if autoquarantining is not enabled in its subnet. It defaults to "0"
which means if you try to quarantine a host for which auto-quar is not
enabled, nothing will happen other than a log entry being made.

This function returns either C<quarantined> if the ip as been quarantined, 
C<nothing> if nothing has been done or C<undef> on failure.

=cut

sub quarantineByIP {
	my $self   = shift;
	my $np	   = $::np;
	my $arrays = 0;
	my @msgs;
    	my $parms = parse_parms({
                             	  -parms    => \@_,
                             	  -legal    => [ qw(-secret -type -id -ip -time -aqo) ],
				  -required => [ qw(-secret -type -id -ip -time) ],
                             	  -defaults => { -secret  => '',
						 -type    => '',
						 -id	  => '',
						 -ip	  => '',
						 -aqo     => 0
                                               }
                            	});

    	return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
    	my ($secret, $type, $id, $ip, $time, $aqo) = $parms->get('-secret', '-type', '-id', '-ip', '-time', '-aqo');

	return undef unless ($self->$check_soap_auth($secret)); 
	return undef if $self->$execute_user_defined_function("quarantineByIP", @_) < 0;

	if (ref($type) eq 'ARRAY' && ref($id) eq 'ARRAY' && ref($time) eq 'ARRAY') {
		$arrays = 1;
	}

	if (!$arrays && (ref($type) eq 'ARRAY' || ref($id) eq 'ARRAY' || ref($time) eq 'ARRAY')) {
		_log("ERROR", "Invalid Paramaters passed");
		return undef;	
	}

	if ($arrays && ($#$type != $#$id || $#$type != $#$time)) {
		_log("ERROR", "LIST Paramaters type, id, and time do not have the same number of elements");
		return undef;
	}

	my $network = $np->cfg->getMatchingNetwork(-ip => $ip);
	if ($network eq "none") {
		_log("ERROR", "Unable to determine network for $ip");
		return undef;
	}

	my $mode = $np->cfg->snortEnabled($network);
	if (!$aqo && $mode eq "disabled") {
		_log("DEBUG", "Snort is disabled on $network");
		return ("nothing");
	}

	my $ip2mac = $np->db->getRegisterInfo(-ip => $ip);
	if (ref($ip2mac) ne 'HASH') {
		_log("ERROR", "Unable to retrieve ip to mac mapping");
		return undef;
	}

	my $mac = $ip2mac->{$ip}->{'macAddress'};
	if (!defined $mac) {
		_log("ERROR", "Cannot determine mac address for $ip");
		return undef;
	}

	if ($arrays) { 
		for (my $i = 0; $i <= $#$type; $i++) {
			my $t = $time->[$i];
			$t    = localtime($time->[$i]) if $time->[$i] =~ /^\d+$/;

			if (!$aqo && $mode eq "not_really") {
				push @msgs, sprintf("%s report-only for violation of %d plugin at %s.",
		                    	            $type->[$i], $id->[$i], $t);
			} else {
				push @msgs, sprintf("%s quarantine for violation of %d plugin at %s.",
						    $type->[$i], $id->[$i], $t);

			}
		}
	} else {
		my $t = $time;
		$t    = localtime($time) if $time =~ /^\d+$/;

		if (!$aqo && $mode eq "not_really") {
			push @msgs, sprintf("%s report-only for violation of %d plugin at %s",
					    $type, $id, $t);
		} else {
			push @msgs, sprintf("%s quarantine for violation of %d plugin at %s.",
				            $type, $id, $t);
		}
	}

	$np->db->audit (
			 -severity	=> 'NOTICE',
			 -mac		=> $mac,
			 -ip		=> $ip,
			 -user		=> 'npapi',
			 -msg		=> \@msgs,
		       );
	return ("nothing") if $mode eq "not_really"; 

	foreach my $npid (($arrays) ? @$id : $id) {
		last if($aqo); # don't log a result if we've got aqo
		my $rv = $np->db->addResult (
				      		-mac	=> $mac,
				      		-id	=> $npid,
						-type	=> ($arrays) ? shift @$type : $type,
					        -npcfg  => $np->cfg
				    	    );

		if ($rv eq "invalid mac") {
			_log("ERROR", "Invalid mac $mac");
			return undef;
		}
		if ($rv eq "db failure") {
			_log("ERROR", "database failure");
			return undef;	
		}
		if ($rv ne "duplicate result" && $rv ne 0) {
			_log("ERROR", "Unknown Error");
			return undef;
		}
	}

        my $rv2 = $np->db->updateRegister (
                                           -mac    => $mac,
                                           -status => "QUAR",
                                          );

        if ($rv2 ne 1) {
        	_log("ERROR", "Unable to quarantine $mac");
                return undef;
        }

	my($sw, $po, $m2p, $p2m) = $np->findOurSwitchPort($mac, $ip);

	if (!defined($sw) || !defined($po)) {
		_log("ERROR", "unable to determine switch for $mac $ip\n");
		return "quarantine pending: unable to determine switch for $mac";
	}

	my $rv3 = $np->db->requestMovePort(
					    -switch 	=> $sw,
					    -port	=> $po,
					    -vlan	=> 'quarantine',
					    -by		=> 'npapi',
					  );

	if (!$rv3) {
		_log("ERROR", "$mac requestMovePort($sw, $po) failed\n");
		return "quarantine pending: requestMovePort($sw, $po) failed";
	}

	return ("quarantined");
}

=head2 my $results = quarantineByMAC(-secret => $secret, -mac => $mac, -id => $id, -type => $type, -time => $time, -aqo => [0 | 1])

Arguments to this function include a secret key, MAC address to be
quarantined, an ID associated to either a Nessus or Snort ID,
a type corresponding to what exactly quarantined this IP, and a timestamp
when the incident occured. The type, ID, and time variables can also be
ARRAY references for multiple id's with their corresponding types and
timestamps, however there must be an equal number of elements in each
of the arrays or an error will occur. 

The aqo ("autoquaroverride") parameter allows you to quarantine a host even
if autoquarantining is not enabled in its subnet. It defaults to "0"
which means if you try to quarantine a host for which auto-quar is not
enabled, nothing will happen other than a log entry being made.

The nr ("no result") parameter allows you to manipulate the results table
from outside the quarantineByMAC function.

This function returns either C<quarantined> if the mac as been quarantined, 
C<nothing> if nothing has been done or C<undef> on failure. If the register
is updated but the quarantine fails, a value of C<quarantine pending: errstr>
is returned since the users register status at that point has been updated to
'QUAR'.

=cut

sub quarantineByMAC {
	my $self   = shift;
	my $np	   = $::np;
	my $arrays = 0;
	my @msgs;
    	my $parms = parse_parms({
                             	  -parms    => \@_,
                             	  -legal    => [ qw(-secret -type -id -mac -time -aqo -nr -status) ],
				  -required => [ qw(-secret -type -id -mac -time) ],
                             	  -defaults => { -secret  => '',
						 -type    => '',
						 -id	  => '',
						 -mac	  => '',
						 -aqo     => 0,
						 -status  => 'QUAR',
                                               }
                            	});

    	return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
    	my ($secret, $type, $id, $mac, $time, $aqo, $nr, $status) = $parms->get('-secret', '-type', '-id', '-mac', '-time', '-aqo', '-nr', '-status');
	
	return undef unless ($self->$check_soap_auth($secret)); 
	return undef if $self->$execute_user_defined_function("quarantineByMAC", @_) < 0;

	if (ref($type) eq 'ARRAY' && ref($id) eq 'ARRAY' && ref($time) eq 'ARRAY') {
		$arrays = 1;
	}

	if (!$arrays && (ref($type) eq 'ARRAY' || ref($id) eq 'ARRAY' || ref($time) eq 'ARRAY')) {
		_log("ERROR", "Invalid Paramaters passed");
		return undef;	
	}

	if ($arrays && ($#$type != $#$id || $#$type != $#$time)) {
		_log("ERROR", "LIST Paramaters type, id, and time do not have the same number of elements");
		return undef;
	}

	my $ip2mac = $np->db->getRegisterInfo(-mac => $mac);
	if (ref($ip2mac) ne 'HASH') {
		_log("ERROR", "Unable to retrieve ip to mac mapping");
		return undef;
	}

	my $ip = $ip2mac->{$mac}->{'ipAddress'};
	if (!defined $ip) {
		_log("ERROR", "Cannot determine ip address for $mac");
		return undef;
	}

	my $network = $np->cfg->getMatchingNetwork(-ip => $ip);
	if ($network eq "none") {
		_log("ERROR", "Unable to determine network for $ip");
		return undef;
	}

	my $mode = $np->cfg->snortEnabled($network);
	if (!$aqo && $mode eq "disabled") {
		_log("DEBUG", "Snort is disabled on $network");
		return ("nothing");
	}

	if ($arrays) { 
		for (my $i = 0; $i <= $#$type; $i++) {
			my $t = $time->[$i];
			$t    = localtime($time->[$i]) if $time->[$i] =~ /^\d+$/;

			if (!$aqo && $mode eq "not_really") {
				push @msgs, sprintf("%s report-only for violation of %d plugin at %s.",
		                    	            $type->[$i], $id->[$i], $t);
			} else {
				push @msgs, sprintf("%s quarantine for violation of %d plugin at %s.",
						    $type->[$i], $id->[$i], $t);

			}
		}
	} else {
		my $t = $time;
		$t    = localtime($time) if $time =~ /^\d+$/;

		if (!$aqo && $mode eq "not_really") {
			push @msgs, sprintf("%s report-only for violation of %d plugin at %s",
					    $type, $id, $t);
		} else {
			push @msgs, sprintf("%s quarantine for violation of %d plugin at %s.",
				            $type, $id, $t);
		}
	}

	$np->db->audit (
			 -severity	=> 'NOTICE',
			 -mac		=> $mac,
			 -ip		=> $ip,
			 -user		=> 'npapi',
			 -msg		=> \@msgs,
		       );
	return ("nothing") if $mode eq "not_really"; 

	unless($nr){
		foreach my $npid (($arrays) ? @$id : $id) {
		 last if($aqo); # don't log a result if we've got aqo
			my $rv = $np->db->addResult (
					      		-mac	=> $mac,
					      		-id	=> $npid,
							-type	=> ($arrays) ? shift @$type : $type,
						        -npcfg  => $np->cfg
				    	    	);

			if ($rv eq "invalid mac") {
				_log("ERROR", "Invalid mac $mac");
				return undef;
			}
			if ($rv eq "db failure") {
				_log("ERROR", "database failure");
				return undef;	
			}
			if ($rv ne "duplicate result" && $rv ne 0) {
				_log("ERROR", "Unknown Error");
				return undef;
			}
		}
	}

        my $rv2 = $np->db->updateRegister (
                                           -mac    => $mac,
                                           -status => $status,
                                          );

        if ($rv2 ne 1) {
        	_log("ERROR", "Unable to quarantine $mac: ".$rv2);
                return undef;
        }

	my($sw, $po, $m2p, $p2m) = $np->findOurSwitchPort($mac, $ip);

	if (!defined($sw) || !defined($po)) {
		_log("ERROR", "unable to determine switch for $mac $ip\n");
		return "quarantine pending: unable to determine switch for $mac $ip";
	}

	my $rv3 = $np->db->requestMovePort(
					    -switch 	=> $sw,
					    -port	=> $po,
					    -vlan	=> 'quarantine',
					    -by		=> 'npapi',
					  );

	if (!$rv3) {
		_log("ERROR", "$mac requestMovePort($sw, $po) failed\n");
		return "quarantine pending: $mac requestMovePort($sw, $po) failed";
	}

	return ("quarantined");
}


=head2 echo()

Used to determine if we have a valid connection, Returns 1 always.

=cut

sub echo {1}

1;
