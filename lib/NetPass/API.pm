package NetPass::API;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw("/opt/netpass/lib);
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

=head2 $aref = getSnortRules(-secret => $secret, -type => $type = <enabled | disabled | all>
			     -ignorequarrule => 0|1)

Retrieve snort rules registered in the NetPass database. Arguments include
a secret, type either return all enabled rules, all disabled rules, or all
rules. Argument ignorequarrule will prepend vlan filtering rules to filter
quarantine traffic from being monitored by snort. Returns an C<array reference>
on success, C<undef> on failure.

=cut

sub getSnortRules {
	my $self   = shift;
	my $np	   = $::np;
	my @aref;

        my $parms = parse_parms({
                                  -parms    => \@_,
                                  -legal    => [ qw(-secret -type -ignorequarrule) ],
                                  -defaults => { -secret  => '',
                                                 -type    => '',
                                                 -ignorequarrule => 0,
                                               }
                                });

        return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
        my ($secret, $type, $ignorequarrule) = $parms->get('-secret', '-type', '-ignorequarrule');

	return undef unless ($self->$check_soap_auth($secret));
	return undef unless ($type =~ /^(enabled|disabled|all)$/);

	my $network = $np->cfg->getNetworks();
	return undef unless (defined ($network));

	_log("DEBUG", "retrieving snort rules");

	if ($ignorequarrule) {
		foreach my $nw (@$network) {
			my $qvlan = $np->cfg->quarantineVlan($nw);
			next unless defined $qvlan;
			push @aref, sprintf("pass tcp any any -> any any (vlan:%d;)\n", $qvlan);

		}
	}

	my $rules = $np->db->getSnortRules($type);
	_log("ERROR", "Unable to retrieve rules from database")
	  	     unless defined($rules);
	return undef unless defined($rules);

	push @aref, @$rules;
	return \@aref;
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

	return $np->cfg->snortEnabled($nw);
}

=head2 my $results = quarantineByIP(-secret => $secret, -ip => $ip, -id => $id, -type => $type)

Arguments to this function include a secret key, ip address to be
quarantined, an id associated to either a Nessus or Snort ID, and
a type corresponding to what exactly quarantined this ip. The type
and id flags can also be ARRAY references for multiple id's with
their corresponding types, however there must be an equal number
of elements in each of the ARRAY or an error will occur. This
function returns either C<quarantined> if the ip as been quarantined,
C<nothing> if nothing has been done or C<undef> on failure.

=cut

sub quarantineByIP {
	my $self   = shift;
	my $np	   = $::np;
	my $arrays = 0;
	my @msgs;
    	my $parms = parse_parms({
                             	  -parms    => \@_,
                             	  -legal    => [ qw(-secret -type -id -ip) ],
                             	  -defaults => { -secret  => '',
						 -type    => '',
						 -id	  => '',
						 -ip	  => '',
                                               }
                            	});

    	return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
    	my ($secret, $type, $id, $ip) = $parms->get('-secret', '-type', '-id', '-ip');

	return undef unless ($self->$check_soap_auth($secret)); 

	if (ref($type) eq 'ARRAY' && ref($id) eq 'ARRAY') {
		$arrays = 1;
	}

	if (!$arrays && (ref($type) eq 'ARRAY' || ref($id) eq 'ARRAY')) {
		_log("ERROR", "Invalid Paramaters passed");
		return undef;	
	}

	if ($arrays && $#$type != $#$id) {
		_log("ERROR", "LIST Paramaters type and id do not have the same number of elements");
		return undef;
	}

	my $network = $np->cfg->getMatchingNetwork(-ip => $ip);
	if ($network eq "none") {
		_log("ERROR", "Unable to determine network for $ip");
		return undef;
	}

	my $mode = $np->cfg->snortEnabled($network);
	if ($mode eq "disabled") {
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
			push @msgs, sprintf("%s quarantine of %s %s for violation of %d plugin.",
		                    	    $type->[$i], $ip, $mac, $id->[$i]);
		}
	} else {
		push @msgs, "$type quarantine of $ip $mac for violation of $id plugin.";
	}

	$np->db->audit (
			 -severity	=> 'NOTICE',
			 -mac		=> $mac,
			 -ip		=> $ip,
			 -user		=> 'npapi',
			 @msgs
		       );
	return ("nothing") if $mode eq "not_really"; 

	foreach my $npid (($arrays) ? @$id : $id) {
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
		if ($rv ne "duplicate result" && $rv != 0) {
			_log("ERROR", "Unknown Error");
			return undef;
		}
	}
	return ("quarantined");
}

=head2 echo()

Used to determine if we have a valid connection, Returns 1 always.

=cut

sub echo {1}

1;
