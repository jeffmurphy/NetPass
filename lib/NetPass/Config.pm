# $Header: /tmp/netpass/NetPass/lib/NetPass/Config.pm,v 1.25 2005/04/24 03:42:02 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package NetPass::Config;
use strict;

require Carp;
require Config::General;

use Data::Dumper;
use FileHandle;
use NetPass::LOG qw(_log _cont);
use NetPass::Network qw(ip2int cidr2int host2addr);

use Class::ParmList qw(simple_parms parse_parms);

=head1 NAME

NetPass::Config - NetPass Configuration File Interface

=head1 SYNOPSIS

    use NetPass::Config;

    $c = new NetPass::Config(-db => NetPass::DB)
    die "Cannot load netpass conf: ". $c->error()
        if ($c->err);

=head1 DESCRIPTION

This object provides access to the NetPass configuration. The configuration
is stored in the database, and so you must pass in a reference to a 
C<NetPass::DB> object. The configuration tracks things such as:

=over 4

=item * 

Types of switches being used on the network and the appropriate NetPass
module to use when controlling those switches,

=item * 

SNMP community names to use,

=item * 

VLAN mappings (switch/port to VLAN tag) for determining what is the 
appropriate "good" and "bad" (quarantine) VLAN tag to use for a given
switch/port,

=item * 

Network-to-Switch mappings incase the management IP of your switches are
not in the same address space as the network(s) that a given switch services.

=back

=head1 METHODS

=cut

my $errstr;

sub xxAUTOLOAD {
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

sub debug {
    my $self = shift;
    my $val  = shift;
    $self->{'dbg'} ||= 0;
    return $self->{'dbg'} unless defined($val);
    $self->{'dbg'} = $val;
    return $self->{'dbg'};
}

sub reloadIfChanged {
    my $self = shift;

    # see if there's a newer rev of the config

    my $newCfg = $self->{'db'}->getConfig();
    if (ref($newCfg) ne "HASH") {
	    _log("WARNING", "couldnt check for new config: $newCfg");
	    return;
    }

    if ($newCfg->{'rev'} > $self->{'cfg_from_db'}->{'rev'}) {
	    # yes, new config available.

	    _log ("DEBUG", "config changed. reloading. cur=".
		  $self->{'cfg_from_db'}->{'rev'}.
		  " new=".$newCfg->{'rev'});

	    $self->{'cfg'} = new Config::General(-String           => $newCfg->{'config'},
						 -AutoTrue         => 1,
						 -IncludeRelative  => 0,
						 -UseApacheInclude => 0,
						 -ExtendedAccess   => 1,
						 -LowerCaseNames   => 1,
						 -StrictObjects    => 0);
	    $self->{'cfg_from_db'} = $newCfg;
    }
}


=head2 my $cfg = new NetPass::Config(-db => NetPass::DB object )

Create a new NetPass configuration object. The config will be
loaded from the database. You can then use this object's methods to
access the configuration attributes. If the config changes in 
the database, we'll detect that and re-load it on the fly.

=cut

sub new {
	my ($class, $self) = (shift, {});
	my $db  = shift;
	my $dbg = shift;
	
	die Carp::longmess("no DB object specified") unless (ref($db) eq "NetPass::DB");
	
	my $rv  = $db->getConfig();
	die Carp::longmess("failed to load config from database: $rv") unless (ref($rv) eq "HASH");

	my $cfg = new Config::General( -String           => $rv->{'config'},
				       -AutoTrue         => 1,
				       -IncludeRelative  => 0,
				       -UseApacheInclude => 0,
				       -ExtendedAccess   => 1,
				       -LowerCaseNames   => 1,
				       -StrictObjects    => 0);
	
	die Carp::longmess("failed to parse configuration") unless defined($cfg);

	$self->{'cfg_from_db'} = $rv;
	$self->{'db'}          = $db;
	$self->{'cfg'}         = $cfg;
	$self->{'dbg'}         = $dbg;
	
	return bless ($self, $class);
}

=head2 my $dbh = $cfg-E<gt>dbSource

Return the database source appropriate for passing into DBI.

=cut

sub dbSource {
    my $self = shift;
    $self->reloadIfChanged();
    return $self->{'cfg'}->obj('database')->value('source')
      if (recur_exists ($self->{'cfg'}, 'database', 'source'));
    return "dbi:mysql:database=netpass";
}

=head2 my $dbuser = $cfg-E<gt>dbUsername

Return the database username appropriate for passing into DBI.

=cut

sub dbUsername {
    my $self = shift;
    $self->reloadIfChanged();
    return $self->{'cfg'}->obj('database')->value('username')
      if (recur_exists ($self->{'cfg'}, 'database', 'username'));
    return "root";
}


=head2 my $dbpass = $cfg-E<gt>dbPassword

Return the database password appropriate for passing into DBI.

=cut

sub dbPassword {
    my $self = shift;
    $self->reloadIfChanged();
    return $self->{'cfg'}->obj('database')->value('password')
      if (recur_exists ($self->{'cfg'}, 'database', 'password'));
    return "";
}

=head2 my $networks = $cfg-E<gt>getNetworks()

Return the list of defined E<lt>networkE<gt>'s. Returns an ARRAY REF on success,
C<undef> on failure.

=cut

sub getNetworks {
    my $self = shift; 
    $self->reloadIfChanged();
    my @nws = $self->{'cfg'}->keys('network');
    return [ @nws ];
}

=head2 $bool = $cfg-E<gt>garp(network, <number | delay>)

If the second parameter is not specified, this routine returns 1 
if garp is enabled on this network, 0 otherwise.

If the second parameter is specified, returns the value of that parameter
or undef if the value is unknown.

=cut

sub garp {
    my $self = shift;
    my $nw   = shift;
    my $dt   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
	_log ("ERROR", "no such network $nw\n");
	return defined($dt) ? undef : 0;
    }

    $dt = "status" unless defined($dt);
    my $s;

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('garp') &&
	$self->{'cfg'}->obj('network')->obj($nw)->obj('garp')->exists($dt) ) {
	$s = $self->{'cfg'}->obj('network')->obj($nw)->obj('garp')->value($dt);
    }
	
    if ($dt =~ /^status$/i) {
	if (defined($s) && ($s =~ /^enabled$/i)) {
	    return 1;
	} else {
	    return 0;
	}
    }

    return $s;
}

=head2 $bool = $cfg-E<gt>interface(network)

Returns the interface defined for this network, else undef.

=cut

sub interface {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
	_log ("ERROR", "no such network $nw\n");
	return undef;
    }

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('interface') ) {
	my $s = $self->{'cfg'}->obj('network')->obj($nw)->value('interface');
	return $s;
    }
    return undef;
}

=head2 $bool = $cfg-E<gt>ha(network)

If HA is enabled, returns 1 else 0.

=cut

sub ha {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
	_log ("ERROR", "no such network $nw\n");
	return 0;
    }

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('ha') &&
        $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('status') ) {
	my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('status');
        return 1 if $s =~ /^enabled$/i;
    }

    return 0;
}

=head2 $bool = $cfg-E<gt>virtualIP(network)

If HA is enabled, returns the virtual IP address assigned to this network. Else undef.

=cut

sub virtualIP {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
	_log ("ERROR", "no such network $nw\n");
	return undef;
    }

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('ha') &&
	$self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('status') ) {

	my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('status');
        return undef unless $s =~ /^enabled$/i;
        
        if ( $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('virtualip') ) {
            return $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('virtualip');
        }

    }
    return undef;
}

=head2 $bool = $cfg-E<gt>primary_redirector(network)

If HA is enabled, returns the primary redirector's hostname assigned to this network. Else undef.

=cut

sub primary_redirector {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
	_log ("ERROR", "no such network $nw\n");
	return undef;
    }

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('ha') &&
	$self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('status') ) {

	my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('status');
        return undef unless $s =~ /^enabled$/i;
        
        if ( $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('primary-redirector') ) {
            return $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('primary-redirector');
        }
    }
    return undef;
}

=head2 $bool = $cfg-E<gt>secondary_redirector(network)

If HA is enabled, returns the secondary redirector's hostname assigned to this network. Else undef.

=cut

sub secondary_redirector {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
        _log ("ERROR", "no such network $nw\n");
        return undef;
    }

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('ha') &&
        $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('status') ) {

        my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('status');
        return undef unless $s =~ /^enabled$/i;

        if ( $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('secondary-redirector') ) {
            return $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('secondary-redirector');
        }
    }
    return undef;
}


=head2 $bool = $cfg-E<gt>ha_servers(network)

If HA is enabled, returns the list of netpass servers assigned to this network. Else undef.

=cut

sub ha_servers {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if( ! $self->{'cfg'}->obj('network')->exists($nw) ) {
	_log ("ERROR", "no such network $nw\n");
	return undef;
    }

    if( $self->{'cfg'}->obj('network')->obj($nw)->exists('ha') &&
	$self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('status') ) {

	my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->value('status');
        return undef unless $s =~ /^enabled$/i;
        
        if ( $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->exists('servers') ) {
            return [ $self->{'cfg'}->obj('network')->obj($nw)->obj('ha')->keys('servers') ];
        }

    }
    return undef;
}

=head2 $port = $cfg-E<gt>npapiPort()

Returns the port npapid will listen on. Else undef.

=cut

sub npapiPort {
    my $self = shift;

    $self->reloadIfChanged();

    if ($self->{'cfg'}->obj('npapi')->exists('port')) {
    	return $self->{'cfg'}->obj('npapi')->value('port');
    }
    return undef;
}

=head2 $secret = $cfg-E<gt>npapiSecret()

Returns the secret used by npapid. Else undef.

=cut

sub npapiSecret {
    my $self = shift;

    $self->reloadIfChanged();

    if ($self->{'cfg'}->obj('npapi')->exists('secret')) {
        return $self->{'cfg'}->obj('npapi')->value('secret');
    }
    return undef;
}

=head2 $bool = $cfg-E<gt>snortEnabled(network)

Determines snort status on the specified network, returns either
enabled, disabled, or not_really on success, 0 on failure.

=cut

sub snortEnabled {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    if (recur_exists($self->{'cfg'}, 'network', $nw, 'snort', 'mode')) {
        my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('snort')->value('mode');
        return $s if ($s =~ /^(enabled|disabled|not_really)$/);
        return 0;
    }

    if (recur_exists($self->{'cfg'}, 'snort', 'mode')) {
        my $s = $self->{'cfg'}->obj('snort')->value('mode');
        return $s if ($s =~ /^(enabled|disabled|not_really)$/);
        return 0;
    }

    return 0;
}

=head2 $sensors = $cfg-E<gt>getSnortSensors(network)

Returns a HASHREF with the keys being address of the machine npsnortd
is running on and the values the port. Returns C<undef> on failure.

=cut

sub getSnortSensors {
    my $self = shift;
    my $nw   = shift;
    my $sensors = {};

    $self->reloadIfChanged();
    return undef unless ($self->snortEnabled($nw) =~ /^(enabled|not_really)$/);

    if (recur_exists($self->{'cfg'}, 'network', $nw, 'snort', 'servers')) {
        my $s = $self->{'cfg'}->obj('network')->obj($nw)->obj('snort');
        foreach ($s->keys('servers')) {
                my($h, $p) = split(':', $_, 2);
                $sensors->{$h} = $p;

        }
        return $sensors;
    }

    if (recur_exists($self->{'cfg'}, 'snort', 'servers')) {
        my $s = $self->{'cfg'}->obj('snort');
        foreach ($s->keys('servers')) {
                my($h, $p) = split(':', $_, 2);
                $sensors->{$h} = $p;

        }
        return $sensors;
    }

    return undef;
}

=head2 my $qvlan = $cfg-E<gt>quarantineVlan(network)

return the id of the quarantined vlan. returns undef if the
id or network is unknown.

=cut

sub quarantineVlan {
        my $self = shift;
        my $nw = shift;

	$self->reloadIfChanged();

        if ($self->{'cfg'}->obj('network')->exists($nw)) {
                if ($self->{'cfg'}->obj('network')->obj($nw)->exists('quarantine')) {
                        return $self->{'cfg'}->obj('network')->obj($nw)->value('quarantine');
                }
        }
        return undef;
}

=head2 my $nqvlan = $cfg-E<gt>nonquarantineVlan(network)

return the id of the nonquarantined vlan. returns undef if the
id or network is unknown.

=cut

sub nonquarantineVlan {
        my $self = shift;
        my $nw = shift;

	$self->reloadIfChanged();

        if ($self->{'cfg'}->obj('network')->exists($nw)) {
                if ($self->{'cfg'}->obj('network')->obj($nw)->exists('nonquarantine')) {
                        return $self->{'cfg'}->obj('network')->obj($nw)->value('nonquarantine');
                }
        }
        return undef;
}

=head2 my $int = $cfg-E<gt>getInterface(network)

return the interface that is connected to the given network. returns undef
if the network is unknown.

=cut

sub getInterface {
        my $self = shift;
        my $nw = shift;

	$self->reloadIfChanged();

        if ($self->{'cfg'}->obj('network')->exists($nw)) {
                if ($self->{'cfg'}->obj('network')->obj($nw)->exists('interface')) {
                        return $self->{'cfg'}->obj('network')->obj($nw)->value('interface');
                }
        }
        return undef;
}

=head2 my $int = $cfg-E<gt>getBSW(network)

return the building switch(es) defined for this network. return C<undef> if no
building switches are defined in the C<netpass.conf> file. 

the value returned will be a space separated list of one or more IP addresses.

e.g.

10.0.0.1 10.0.0.2 10.0.0.3

or just

10.0.0.1

=cut

sub getBSW {
        my $self = shift;
        my $nw = shift;

	$self->reloadIfChanged();

	my $e_n   = $self->{'cfg'}->obj('network')->exists($nw);
	my $s_e   = $self->{'cfg'}->obj('network')->obj($nw)->exists('switches');
	my $bsw_e = $self->{'cfg'}->obj('network')->obj($nw)->obj('switches')->exists('bsw');

	if ($e_n && $s_e && $bsw_e) {
	    return $self->{'cfg'}->obj('network')->obj($nw)->obj('switches')->value('bsw');
	}

        return undef;
}

=head2 my $switches = $cfg-E<gt>getSwitches(network)

Return the list of switches defined for this E<lt>networkE<gt>. Returns an ARRAY REF
on success, C<undef> on failure. If "network" is "", then we return all configured 
switches.

=cut


sub getSwitches {
    my ($self, $network) = (shift, shift);
    $self->reloadIfChanged();

    my @switches;
    my %switches;

    if (defined($network) && ($network ne "")) {
	    # exclude the "bsw" keyword
	    @switches = grep { !/^bsw$/i } $self->{'cfg'}->obj('network')->obj($network)->keys('switches');
	    foreach my $sw (@switches) {
		    $switches{$sw} = 1;
	    }
    } else {
	    my $nws = $self->getNetworks();
	    foreach my $nw (@$nws) {
		    push @switches, grep { !/^bsw$/i } $self->{'cfg'}->obj('network')->obj($nw)->keys('switches');
		    foreach my $sw (@switches) {
			    $switches{$sw} = 1;
		    }
	    }
    }

    return [ keys %switches ];
}

=head2 my $comment = $cfg-E<gt>getNetComment($network)

Given a network, return the comment that is configured, or "" if no 
comment is specified.

=cut


sub getNetComment {
    my ($self, $network) = (shift, shift);

    $self->reloadIfChanged();

    if( $self->{'cfg'}->obj('network')->exists($network) ) {
	    if( $self->{'cfg'}->obj('network')->obj($network)->exists('comment') ) {
		    return $self->{'cfg'}->obj('network')->obj($network)->value('comment');
	    }
    }
    return "";
}


=head2 $val = $np->policy(-key => $key, -network => $nw, -val => $value)

FETCHING POLICY SETTINGS

=over 4

Given a key (a policy/configuration variable name) return the associated value
or undef if the variable doesnt exist in the C<netpass.conf>
E<lt>policyE<gt> section. 

Networks can have E<lt>policyE<gt> sections too. If we're given a network, 
we'll search there first. If we don't find anything useful, we'll try the network's 
group and finally the global policy.

=back

SETTING POLICY SEETINGS

=over 4

If a -val is given, the policy variable will be set instead of fetched. If no
network is specified, the global policy is set. If a network is specified, 
the specific policy for the network is set. If a groupname is given, the 
specific policy for that group is set.

=back

RETURN VALUES

=over 4

 HASHREF           on successful fetch: { 'key' => 'value' }
 HASHREF           on successful set:   { 'key' => 'oldvalue' }
 "invalid parameters"
                   routine called improperly
 "config not loaded"
                   failed to read config
 "nosuch network"  attempt to set a policy on invalid network
 "nosuch group"    attempt to set a policy on invalid group

=back

=cut

sub policy {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-key -network -val)],
				 -required => [qw(-key)],
				 -defaults => { -network => '', -val => undef }
			    }
			   );
	return Carp::longmess("invalid parameters ".Class::ParmList->error) if (!defined($parms));

	my ($pvar, $nw, $val) = $parms->get('-key', '-network', '-val');


	_log("DEBUG", "policy($pvar)\n") if $self->debug;

	$nw = "" if ($nw eq "default");
	$nw ||= "";

	$self->reloadIfChanged();
	
	return "config not loaded"
	  if (! exists $self->{'cfg'}) || 
	    (ref $self->{'cfg'} ne "Config::General::Extended");
	
	$pvar =~ tr [A-Z] [a-z]; # because of AutoLowerCase

	# if network looks like an IP, figure out which <network> clause
	# applies. else we assume network is a group name (if it's defined
	# at all)

	if ($nw !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) { 
		_log("DEBUG", "policy($pvar): resolve nw=$nw\n") if $self->debug;
		$nw = $self->getMatchingNetwork(-ip => $nw);
		_log("DEBUG", "policy($pvar): resolved to nw=$nw\n") if $self->debug;
	} 


	# this is a lookup operation

	if ( !defined($val) ) {
		# if the network has a <policy> section, check it for the given
		# pvar

		if (recur_exists ($self->{'cfg'}, "network", $nw, "policy", $pvar)) {
			_log("DEBUG", "policy($pvar): nw=$nw has policy section. returning that.\n") if $self->debug;
			return { $pvar => $self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->value($pvar) };
		}


		# if the network has a group name, check the group

		my $netgroup = "";
		if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
			$netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
			_log("DEBUG", "policy($pvar): nw=$nw is member of group $netgroup\n") if $self->debug;
			if (recur_exists ($self->{'cfg'}, "group", $netgroup, "policy", $pvar)) {
				_log("DEBUG", "policy($pvar): (nw=$nw) group=$netgroup has policy section. returning that.\n") if $self->debug;
				return { $pvar => 
					 $self->{'cfg'}->obj('group')->obj($netgroup)->obj('policy')->value($pvar) };
			}
		}

		# finally, look in the global policy

		_log("DEBUG", "policy($pvar): looking in global policy.\n") if $self->debug;
		
		return { $pvar => $self->{'cfg'}->obj('policy')->value($pvar) }
		  if (recur_exists ($self->{'cfg'}, "policy", $pvar));
		
		_log("DEBUG", "policy($pvar): no global policy. $pvar not found.\n") if $self->debug;

		return { $pvar => undef };
	} 

	# this is a set operation

	else {
		my $oldvalue = undef;

		if ($nw !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) { 
			# set the <network>'s policy

			if (! recur_exists ($self->{'cfg'}, "network", $nw)) {
				return "nosuch network";
			}

			if (! recur_exists ($self->{'cfg'}, "network", $nw, "policy")) {
				# create one
				$self->{'cfg'}->obj('network')->obj($nw)->policy({});
			}

			if ( recur_exists ($self->{'cfg'}, "network", $nw, "policy", $pvar) ) {
				$oldvalue = $self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->value($pvar);
				$self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->$pvar($val);
				return { $pvar => $oldvalue };
			}
		} 
		elsif ($nw ne "") {
			# set the <group> policy

			if (! recur_exists ($self->{'cfg'}, "group", $nw)) {
				return "nosuch group";
			}

			if (! recur_exists ($self->{'cfg'}, "group", $nw, 'policy')) {
				# create one
				$self->{'cfg'}->obj('network')->obj($nw)->policy({});
			}

			if ( recur_exists ($self->{'cfg'}, "network", $nw, "policy", $pvar) ) {
				$oldvalue = $self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->value($pvar);
				$self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->$pvar($val);
				return { $pvar => $oldvalue };
			}

			$self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->$pvar($val);
			return { $pvar => undef };

		}
		else {
			if (! recur_exists($self->{'cfg'}, "policy") ) {
				# create one
				$self->{'cfg'}->policy({});
			}

			if (recur_exists ($self->{'cfg'}, "policy", $pvar) ) {
				$oldvalue = $self->{'cfg'}->obj('policy')->value($pvar);
			}
			$self->{'cfg'}->obj('policy')->$pvar($val);
			return { $pvar => $oldvalue };
		}

	}

	return undef;
}

=head2 my $network = $cfg-E<gt>getMatchingNetwork(-ip => $ip, -switch => $ip, -port => $port)

Return the network that the specified IP is a part of. If IP is 
omitted and switch/port given instead, then return the network that
the switch port is configured for. 

Returns

=over

=item B<network> 

In CIDR notication, on success.

=item B<"invalid parameters">

Routine was called improperly.

=item B<"none">

If no network was found that matches.

=back

=cut

sub getMatchingNetwork {
    my $self = shift;

    $self->reloadIfChanged();

    my $parms = parse_parms({
			     -parms    => \@_,
			     -legal    => [qw(-switch -port -ip)],
			     -defaults => { -ip => '', -switch => '', -port => '' }
			    }
			   );

    return Carp::longmess("invalid parameters ".Class::ParmList->error) if (!defined($parms));
    
    my ($ip, $sw, $po) = $parms->get('-ip', '-switch', '-port');

    return "invalid parameters (if !ip then sw/po both reqd)"
      if (($ip eq "") && (($sw eq "") || ($po eq "")));

    if ($ip ne "") {
	    _log("DEBUG", qq{ip="$ip"\n}) if $self->debug;

	    if ($ip =~ /\//) { # looks like a network already
		    if (recur_exists($self->{'cfg'}, "network", $ip)) {
			    return $ip;
		    } else {
			    return "none";
		    }
	    }

	    my $ip_ = ip2int(host2addr($ip));
	    
	    foreach my $n ($self->{'cfg'}->keys('network')) {
		    my ($n_, $m_) = cidr2int($n);
		    _log("DEBUG", sprintf("%x & %x ? %x (%x)\n", $ip_, $m_, $n_,
					  ($ip_ & $m_))) if $self->debug > 1;
		    return $n if ( ($ip_ & $m_) == $n_);
	    }
    } 
    else {
	    _log("DEBUG", qq{sw=$sw port=$po\n}) if $self->debug;

	    # fetch the vlans for the given switch port

	    my ($uqvl1, $qvl1) = $self->availableVlans(-switch => $sw, -port => $po);

	    return "none" if !defined($uqvl1);

	    # look thru each network until you find one that matches
	    # the vlans

	    foreach my $n ($self->{'cfg'}->keys('network')) {
		    my ($uqvl2, $qvl2) = $self->availableVlans(-network => $n);
		    next if ($uqvl2 eq "" || $qvl2 eq "");
		    return $n if ( ($uqvl1 == $uqvl2) && ($qvl1 == $qvl2) );
	    }
    }

    return "none";
}

sub getNetgroup {
	my $self    = shift;
	my $network = shift;
	my $nw = $self->getMatchingNetwork(-ip => $network);
	my $netgroup = '';

	if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
		$netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
	}

	return $netgroup;
}

=head2 my ($r, $w) = $cfg-E<gt>getCommunities(hostname)

Given a hostname (or IP address) lookup return the
SNMP read and write community names.

=cut

sub getCommunities {
    my $self = shift;
    my $hn   = shift;
    
    $self->reloadIfChanged();
    
    #_log "DEBUG", "hn=$hn\n";
    
    my $a    = host2addr($hn);
    
    # first check for a specific <host *> record by name
    
    my $nw = undef;
    
    if( recur_exists($self->{'cfg'}, 'snmpcommunities', 'host', $hn) ) {
	_log "DEBUG", "found exact host match for hn=$hn\n" if $self->{'dbg'};

	return ($self->{'cfg'}->obj('snmpcommunities')->obj('host')->obj($hn)->value('read'),
		$self->{'cfg'}->obj('snmpcommunities')->obj('host')->obj($hn)->value('write'));

    } 

    # next, check if there's an exact <host> match by address

    elsif ( recur_exists($self->{'cfg'}, 'snmpcommunities', 'host', $a) ) {
	_log "DEBUG", "found exact host match for a=$a\n" if $self->{'dbg'};

	return ($self->{'cfg'}->obj('snmpcommunities')->obj('host')->obj($a)->value('read'),
		$self->{'cfg'}->obj('snmpcommunities')->obj('host')->obj($a)->value('write'));
    }

    # finally, search by network

    else {
	_log "DEBUG", "no exact host match ($hn / $a). search by network\n" if $self->{'dbg'};
	
	# using the address, enumerate each network and see if our host
	# is on one of them. stop on the first match.
	    
	my $a_ = ip2int($a);
 
	foreach my $nw_ ( $self->{'cfg'}->obj('snmpcommunities')->keys('network') ) {
		_log "DEBUG", "is $a on $nw_?\n" if $self->{'dbg'};
		my ($n, $m) = cidr2int($nw_);
		if ( ($a_ & $m) == $n ) {
			_log "DEBUG", "yes.\n" if $self->{'dbg'};
			$nw = $nw_; #perlism
			last;
		} 
		_log "DEBUG",  "no.\n" if $self->{'dbg'};
	}
	
	if( defined($nw) ) {
		_log "DEBUG", "net is $nw\n" if $self->{'dbg'};
		
		return ($self->{'cfg'}->obj('snmpcommunities')->obj('network')->obj($nw)->value('read'),
			$self->{'cfg'}->obj('snmpcommunities')->obj('network')->obj($nw)->value('write'));
		
		
	} else {
		_log "DEBUG", "no matching network for $a\n" if $self->{'dbg'};
		return (undef, undef);
	}
    }
    return (undef, undef);
}

=head2 my $portsArrayRef = $cfg-E<gt>configuredPorts(host)

Given a hostname/IP of a switch return the list of ports we're configured to manage
on that switch. Returns an ARRAY REF on success, C<undef> on failure.

=cut

sub configuredPorts {
    my $self = shift;
    my $h = shift;

    $self->reloadIfChanged();
 
    my $a    = host2addr($h);

    # first, determine if we have a mapping for the specified hostname


    _log "DEBUG", "try to match VLANMAP by hostname ($h)\n" if $self->{'dbg'};
    
    if ($self->{'cfg'}->obj('vlanmap')->exists($h)) {
	_log "DEBUG", "matched.\n" if $self->{'dbg'};
	my $tagList = expandTagList($self->{'cfg'}->obj('vlanmap')->value($h));
	return [ keys %$tagList ];
    }
    
    # otherwise, see if we can match on the IP
    
    else {
	_log "DEBUG", "try to match VLANMAP by IP\n" if $self->{'dbg'};
	
	if ($self->{'cfg'}->obj('vlanmap')->exists($a)) {
	    _log "DEBUG", "matched.\n" if $self->{'dbg'};
	    my $tagList = expandTagList($self->{'cfg'}->obj('vlanmap')->value($a));
	    return [ keys %$tagList ];
	}
    }
    
    # finally, see if we can match by network
    
    _log "DEBUG", "try to match VLANMAP by network\n" if $self->{'dbg'};
    
    my $a_ = ip2int($a);
    my $nw;
    
    foreach my $nw_ ( $self->{'cfg'}->keys('vlanmap') ) {
	_log "DEBUG", "is $a on $nw_?\n" if $self->{'dbg'};
	my ($n, $m) = cidr2int($nw_);
	if ( ($a_ & $m) == $n ) {
	    _log "DEBUG", "yes.\n" if $self->{'dbg'};
	    $nw = $nw_; #perlism
	    last;
	}
	_log "DEBUG", "no.\n" if $self->{'dbg'};
    }
    
    if( defined($nw) ) {
	_log "DEBUG", "net is $nw\n" if $self->{'dbg'};
	my $tagList =  expandTagList($self->{'cfg'}->obj('vlanmap')->value($nw));
	return [ keys %$tagList ];
    } else {
	_log "DEBUG", "no matching network for $a\n" if $self->{'dbg'};
    }
    
    return undef;
}


=head2 my @tagList = $cfg-E<gt>availableVlans(-host => host, -port => port)

=head2 my @tagList = $cfg-E<gt>availableVlans(-network => network)

Given a hostname (or IP) and a port, return the list of available tags
for that port. This list will always be two elements. The first is the 
"good" vlan and the second is the "quarantine" vlan. Returns:

=over 4

=item ($good, $bad)

a two element list of integers

=item C<undef> 

if we can't determine the answer

=back

=cut

sub availableVlans {
    my $self = shift;

    $self->reloadIfChanged();
    
    my $parms = parse_parms({
			     -parms => \@_,
			     -legal => [qw(-switch -port -interface -vlan -network)]
			    }
			   );
    die Carp::longmess("availableVlans: ".Class::ParmList->error) if (!defined($parms));
    
    my ($h, $p, $if, $vid, $nw) = $parms->get('-switch', '-port', '-interface', '-vlan',
					 '-network');
    
    my $av;
    if (defined($if) && defined($vid)) {
	return $self->availableVlans_interface_and_vlan($if, $vid);
    }
    elsif (defined($nw)) {
	return $self->availableVlans_network($nw);
    } else {
	$av = $self->availableVlansRE_switch_and_port($h, $p);
    }
    
    return undef if !defined($av);
    return split(/\|/, $av);
}

sub availableVlans_network {
    my $self      = shift;
    my $network   = shift;

    $self->reloadIfChanged();
    
    if( $self->{'cfg'}->obj('network')->exists($network) ) {
	my $netObj = $self->{'cfg'}->obj('network')->obj($network);
	my ($g, $b) = ($netObj->value('nonquarantine'),
		       $netObj->value('quarantine'));
	return ($g, $b);
    }
    return undef;
}

sub availableVlans_interface_and_vlan {
    my $self      = shift;
    my $interface = shift;
    my $vid       = shift;
    
    $self->reloadIfChanged();
    
    foreach my $nw ($self->{'cfg'}->keys('network')) {
	my $netObj = $self->{'cfg'}->obj('network')->obj($nw);
	if ($netObj->value('interface') eq $interface) {
	    my ($g, $b) = ($netObj->value('nonquarantine'),
			   $netObj->value('quarantine'));
	    
	    return ($g, $b) if ( ($g == $vid) || ($b == $vid) );
	}
    }
    return undef;
}

sub availableVlansRE_switch_and_port {
    my $self = shift;
    my ($h, $p) = (shift, shift);
    
    $self->reloadIfChanged();
    
    my $a    = host2addr($h);
    
    # first, determine if we have a mapping for the specified hostname
    
    _log("DEBUG", "try to match VLANMAP by hostname\n") if $self->debug;
    
    if ($self->{'cfg'}->obj('vlanmap')->exists($h)) {
	_log("DEBUG", "matched.\n") if $self->debug;
	my $tagList = expandTagList($self->{'cfg'}->obj('vlanmap')->value($h));
	return $tagList->{$p} if (exists $tagList->{$p});
	return undef;
    }
    
    # otherwise, see if we can match on the IP
    
    else {
	_log("DEBUG", "try to match VLANMAP by IP\n") if $self->debug;
	
	if ($self->{'cfg'}->obj('vlanmap')->exists($a)) {
	    _log("DEBUG", "matched.\n") if $self->debug;
	    my $tagList = expandTagList($self->{'cfg'}->obj('vlanmap')->value($a));
	    return $tagList->{$p} if (exists $tagList->{$p});
	    return undef;
	}
    }
    
    # finally, see if we can match by network
    
    _log("DEBUG", "try to match VLANMAP by network\n") if $self->debug;
    
    my $a_ = ip2int($a);
    my $nw;
    
    foreach my $nw_ ( $self->{'cfg'}->keys('vlanmap') ) {
	_log("DEBUG", "is $a on $nw_?\n") if $self->debug;
	my ($n, $m) = cidr2int($nw_);
	if ( ($a_ & $m) == $n ) {
	    _log("DEBUG", "yes.\n") if $self->debug;
	    $nw = $nw_; #perlism
	    last;
	}
	_log("DEBUG", "no.\n") if $self->debug;
    }
    
    if( defined($nw) ) {
	_log("DEBUG", "net is $nw\n") if $self->debug;
	my $tagList =  expandTagList($self->{'cfg'}->obj('vlanmap')->value($nw));
	return $tagList->{$p} if (exists $tagList->{$p});
    } else {
	_log("DEBUG", "no matching network for $a\n") if $self->debug;
    }
    
    return undef;
}

=head2 my $bool = $cfg-E<gt>isVlanAvailable(host, port, vlan)

Given a hostname (or IP address) and a port, determine if the specified
tag is valid for that switch/port. Returns:

=over 4

=item 0 

if VLAN tag is not available on this port

=item 1 

if it is available

=item C<undef>

 if we don't know the answer

=back

=cut

sub isVlanAvailable {
	my $self = shift;
	my ($h, $p, $v) = (shift, shift, shift);
	
	$self->reloadIfChanged();
	
	my ($good, $bad) = $self->availableVlans(-switch => $h, -port => $p);
	
	return undef if (!defined($good) || !defined($bad));
	return ($good == $v || $bad == $v) ? 1 : 0;
}


# tagList format:
#    port1,port3-port5:good/bad;port7-port10:good/bad
#
# e.g. if the switch services multiple networks (2 in this case)
#
#   1,10-20:12/812;2-9,21-24:13/813
#
# or more simply, you'll typically have:
#
#   1-24:12/812
#
# where '12' is the 'good/normal' vlan and '812' is the quarantine

sub expandTagList {
	my $tl   = shift;
	my $etl;
	
	# first split around semicolons
	
	foreach my $part (split(';', $tl)) {
		
		# next, split around colon into portlist and vlan map
		
		my ($pl, $vm) = split(':', $part);
		
		die Carp::longmess(qq{malformed vlanmap. should be "portlist:vlanmap" but is "$part"})
		  unless defined($pl) && defined($vm);
		
		# next, expand the port list and convert the mapping into a regexp
		# (we dont actually use the RE anywhere apparently)
		
		die Carp::longmess(qq{vlanmap should be D/D but is "$vm"}) 
		  unless $vm =~ /^\d+\/\d+/;
		
		$vm =~ s/\//\|/;
		
		# split portlist around comma
		
		foreach my $port (split(',', $pl)) {
			
			# if the port is a range (a-b) then expand the range
			# else just record the port directly
			
			if ($port =~ /^(\d+)\-(\d+)$/) {
				foreach my $p ( $1 .. $2 ) {
					$etl->{$p} = $vm;
				}
			} else {
				$etl->{$port} = $vm;
			}
			
		} #foreach comma split
		
	} #foreach semi split
	
	return $etl;
}

=head2 B<$np->cfg->nessusBaseDir()>


=cut

sub nessusBaseDir {
	my $self = shift;
	$self->reloadIfChanged();
	return $self->{'cfg'}->obj('nessus')->value('BASE_DIR');
}

=head2 B<$np->cfg->nessusUsername()>


=cut

sub nessusUsername {
	my $self = shift;
	$self->reloadIfChanged();
	return $self->{'cfg'}->obj('nessus')->value('username');
}

=head2 B<$np->cfg->nessusPassword()>


=cut

sub nessusPassword {
	my $self = shift;
	$self->reloadIfChanged();
	return $self->{'cfg'}->obj('nessus')->value('password');
}

=head2 B<$np->cfg->nessusHost()>


=cut

sub nessusHost {
	my $self = shift;
	$self->reloadIfChanged();
	return $self->{'cfg'}->obj('nessus')->value('host');
}

=head2 B<$np->cfg->nessusPort()>


=cut

sub nessusPort {
	my $self = shift;
	$self->reloadIfChanged();
	return $self->{'cfg'}->obj('nessus')->value('port');
}

=head2 B<$np->cfg->nessusConfig()>


=cut

sub nessusConfig {
	my $self = shift;
	my $val  = shift;
	$val =~ tr [A-Z] [a-z];

	$self->reloadIfChanged();

	return $self->{'cfg'}->obj('nessus')->value($val)
	  if (recur_exists($self->{'cfg'}, 'nessus', $val));
}

=head2 B<recur_exists>

This is a routine, not a method. Useful for checking if a deep configuration
parameter exists in the configuration file. 

=cut

sub recur_exists {
	my $cr = shift;
	my $kn = shift;

	return 0 if !$cr->exists($kn);
	return 1 if $cr->exists($kn) && ($#_ == -1);
	return recur_exists($cr->obj($kn), @_);
}

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 CREDITS

This module uses L<Config::General> to do all the parsing of the 
configuration file.

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: Config.pm,v 1.25 2005/04/24 03:42:02 jeffmurphy Exp $

=cut

1;
