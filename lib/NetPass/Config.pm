# $Header: /tmp/netpass/NetPass/lib/NetPass/Config.pm,v 1.56 2006/03/23 18:50:04 jeffmurphy Exp $

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
	    _log("ERROR", "couldnt check for new config: $newCfg");
	    return;
    }

    if ($newCfg->{'rev'} > $self->{'cfg_from_db'}->{'rev'}) {
	    # yes, new config available.

	    _log ("DEBUG", "config changed. reloading. cur=".
		  $self->{'cfg_from_db'}->{'rev'}.
		  " new=".$newCfg->{'rev'}."\n");

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

=head2 $cfg-E<gt>save(-user => whoareyou)

Save the current configuration. We don't attempt to acquire
a lock on the config. You should have already gotten one before
you started to edit it. 

RETURNS 

=over 4

 0         on success
 "..."     on failure (can be a variety of things)

=back 

=cut

sub save {
	my $self = shift;


        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-user)],
				 -required => [qw(-user)]
			    }
			   );

	if (!defined($parms)) {
		return  Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($user) = $parms->get('-user');

	my $rv = $self->{'db'}->putConfig(-rev    => $self->{'cfg_from_db'}->{'rev'},
				       -config => [ $self->{'cfg'}->save_string() ],
				       -user   => $user);
	return $rv;
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

If HA is enabled, returns the list (ARRAYREF) of netpass servers assigned to this network. 
Else undef.

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

=head2 $val = snort(-key => $key, -network => $nw, -val => $value, -sval => $subvalue, -del => 0|1 )

FETCHING SNORT SETTINGS

=over 4

Given a key (a snort variable name) and optionally a -sval subvalue return the associated value
or undef if the variable doesnt exist in the C<netpass.conf> E<lt>snortE<gt> section.

Networks can have E<lt>snortE<gt> sections too. If we're given a network,
we'll search there first. If we don't find anything useful, we'll try the network's
group and finally the global snort section.

=back

SETTING SNORT SETTINGS

=over 4

If a -val and optionally a -sval is given, the snort variable will be set instead of
fetched. If no network is specified, the global snort section is set. If a network
is specified, the specific snort section for the network is set. If a groupname is
given, the specific snort section for that group is set.

=back

DELETE SNORT SETTINGS

=over 4

If a -key and optionally a -sval is given when -del is true the associated value of 
-key will be deleted.

=back


RETURN VALUES

=over 4

 value (even undef)  on successful fetch or set

=back

=cut

sub snort {
        my $self = shift;

        my $parms = parse_parms({
                                 -parms => \@_,
                                 -legal => [qw(-key -network -val -sval -del)],
                                 -required => [qw(-key)],
                                 -defaults => { -network => '', -val => undef, -sval => undef, -del => 0}
                            }
                           );

        if (!defined($parms)) {
                _log("ERROR", Carp::longmess("invalid parameters ".Class::ParmList->error)."\n");
                return undef;
        }

	my ($pvar, $nw, $val, $sval, $del) = $parms->get('-key', '-network', '-val', '-sval', '-del');

	$del = 0 if $del != 1;
        $nw = "" if ($nw eq "default");
        $nw ||= "";

	$self->reloadIfChanged();

	$pvar =~ tr [A-Z] [a-z]; # because of AutoLowerCase
	$sval =~ tr [A-Z] [a-z]; # because of AutoLowerCase

        # if network looks like an IP, figure out which <network> clause
        # applies. else we assume network is a group name (if it's defined
        # at all)

        if ($nw =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) {
                $nw = $self->getMatchingNetwork(-ip => $nw);
        }

	if ($del == 1) {
		my $cobj;
                if ($nw =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) {
                        if (! recur_exists ($self->{'cfg'}, "network", $nw)) {
                                return undef; #"nosuch network";
                        }
                        $cobj = $self->{'cfg'}->obj('network')->obj($nw)->obj('snort');
                } elsif ($nw ne "") {
                        $nw =~ s/\s/\%20/g; # Config::General bug workaround
                                                    # reported 3-may-2005
                        $nw =~ tr [A-Z] [a-z]; # another Config::General bug

                        if (! recur_exists ($self->{'cfg'}, "group", $nw)) {
                                return undef; #"nosuch group";
                        }

                        $cobj = $self->{'cfg'}->obj('group')->obj($nw)->obj('snort');
                } else {
                        $cobj = $self->{'cfg'}->obj('snort');
                }

		return 0 unless defined $cobj;

                if (defined $sval) {
                        $cobj->obj($sval)->delete($pvar) if (recur_exists($cobj, $sval, $pvar));
                } else {
                        $cobj->delete($pvar) if $cobj->exists($pvar);
                }
		return 1;
	} elsif ( !defined $val) {
	        # get config object for snort
	        my $cobj;

		my @var;
		push @var, $sval if $sval ne "";
		push @var, $pvar;
	
	        if (recur_exists ($self->{'cfg'}, "network", $nw, "snort", @var)) {
	                $cobj =  $self->{'cfg'}->obj('network')->obj($nw)->obj('snort');
	        }

	        # if the network has a group name, check the group

	        if (!$cobj) {
	                my $netgroup = "";
	                if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
	                        $netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
	                        $netgroup =~ s/\s/\%20/g; # Config::General bug workaround
	                                                  # reported 3-may-2005 (see once more below!)
	                        $netgroup =~ tr [A-Z] [a-z]; # another Config::General bug
	                                                     # reported 3-may-2005

	                        if (recur_exists ($self->{'cfg'}, "group", $netgroup, "snort", @var)) {
	                                $cobj = $self->{'cfg'}->obj('group')->obj($netgroup)->obj('snort');
	                        }
	                }
	        }

	        # if the above didnt work, perhaps we were given a group name

	        if (!$cobj) {
	                my $netgroup = $nw;
	                $netgroup =~ s/\s/\%20/g; # Config::General bug workaround
	                $netgroup =~ tr [A-Z] [a-z]; # another Config::General bug
	                if (recur_exists($self->{'cfg'}, "group", $netgroup)) {
	                        if (recur_exists($self->{'cfg'}, 'group', $netgroup, 'snort', @var)) {
	                                $cobj = $self->{'cfg'}->obj('group')->obj($netgroup)->obj('snort');
	                        }
	                }
	        }

	        # finally, look in the global snort

	        if (!$cobj) {
	                $cobj =  $self->{'cfg'}->obj('snort')
	                  if (recur_exists ($self->{'cfg'}, "snort", @var));
	        }

		return 0 unless defined $cobj;

		if ($sval) {
			return $cobj->obj($sval)->value($pvar) if recur_exists($cobj, $sval, $pvar);
		} else {
			return $cobj->value($pvar) if $cobj->exists($pvar);
		}
	} elsif ( defined $val) {
		my $cobj;

		# determine if we need to add a <snort> clause
		if ($nw =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) {
			# add snort to network

                       	if (! recur_exists ($self->{'cfg'}, "network", $nw)) {
                               	return undef; #"nosuch network";
                       	}

			$self->{'cfg'}->obj('network')->obj($nw)->snort({})
				unless recur_exists ($self->{'cfg'}, "network", $nw, "snort");
			$cobj = $self->{'cfg'}->obj('network')->obj($nw)->obj('snort');
		} elsif ($nw ne "") {
			# add <snort> to netgroup				

                       	$nw =~ s/\s/\%20/g; # Config::General bug workaround
                                           	    # reported 3-may-2005
                       	$nw =~ tr [A-Z] [a-z]; # another Config::General bug

                        if (! recur_exists ($self->{'cfg'}, "group", $nw)) {
                               	return undef; #"nosuch group";
                      	}

			$self->{'cfg'}->obj('group')->obj($nw)->snort({})
				unless recur_exists ($self->{'cfg'}, "group", $nw, "snort");
			$cobj = $self->{'cfg'}->obj('group')->obj($nw)->obj('snort');	
		} else {
			# add <snort> to global		

			$self->{'cfg'}->snort({})
				unless recur_exists ($self->{'cfg'}, "snort");
			$cobj = $self->{'cfg'}->obj('snort');
		}
		if ($sval) {
			if (recur_exists($cobj, $sval)) {
				$cobj->obj($sval)->$pvar($val);
			} else {
				$cobj->$sval({});
				$cobj->obj($sval)->$pvar($val);
			}		
			return 1;
		} else {
			$cobj->$pvar($val);
			return 1;
		}
	}

	return undef;
}

=head2 snortLocation(-key => '', -sval => '', -network => '', -location => [''|first|global|group|network])

Check if a given snort variable is set in the specified location. If location
is '', then we return an ARRAY ref that contains the locations the given
variable was found in. Otherwise we return 0 or 1 based on whether or not
we found the variable in the specified location.

If "first" is given as the location, then we'll start at the most specific scope possible
and work towards the most general scope. The first time we see the variable, we'll
return the scope that we are at.

RETURNS

  0                     not found in specified location
  1                     found in specified location
  "network"             found here "first"
  "group"               found here "first"
  "global"              found here "first"
  ARRAYREF              found in the following locations (may be empty)
  "invalid parameters"  routine called incorrectly

=cut

sub snortLocation {
        my $self = shift;
	my @var;

        my $parms = parse_parms({
                                 -parms => \@_,
                                 -legal => [qw(-key -network -sval -location)],
                                 -required => [qw(-key)],
                                 -defaults => { -network => '', -sval => '', -location => '' }
                            }
                           );

        if (!defined($parms)) {
                return "invalid parameters ". Carp::longmess("invalid parameters ".Class::ParmList->error);
        }

        my ($pvar, $nwOrig, $sval, $location) = $parms->get('-key', '-network', '-sval', '-location');


        $pvar =~ tr [A-Z] [a-z]; # AutoLowerCase
        $sval =~ tr [A-Z] [a-z]; # AutoLowerCase
        $nwOrig = "" if ($nwOrig eq "default");

        my $rv = [];
        my $nw = $self->getMatchingNetwork(-ip => $nwOrig);

	push @var, $sval if $sval ne "";
	push @var, $pvar;

        if ($nw && ($nw ne "none")) {
                return 0
                  if ($location eq "network" && !recur_exists($self->{'cfg'}, 'network',
                                                              $nw, 'snort', @var));

                if (recur_exists($self->{'cfg'}, 'network', $nw, 'snort', @var)) {
                        return 1 if ($location eq "network");
                        return "network" if ($location eq "first");
                        push @$rv, "network";
                }

                # if this network is part of a netgroup, check there too

                my $ng = $self->getNetgroup(-network => $nw);
                if ($ng) {
                        $ng =~ s/\s/%20/g;
                        $ng =~ tr [A-Z] [a-z];
                        push @$rv, "group"
                          if (recur_exists($self->{'cfg'}, 'group', $ng, 'snort', @var));
                }
        }
        else {
                # perhaps this is a netgroup?
                my $nw2 = $nwOrig;
                $nw2 =~ s/\s/%20/g; # Config::General bug
                $nw2 =~ tr [A-Z] [a-z]; # Config::General bug

                if (($location eq "group") && !recur_exists($self->{'cfg'}, 'group',
                                                            $nw2, 'snort', @var)) {
                        return 0;
                }

                if (recur_exists($self->{'cfg'}, 'group', $nw2, 'snort', @var)) {
                        return 1 if ($location eq "group");
                        return "group" if ($location eq "first");
                        push @$rv, "group";
                }
        }


        return 0
          if ($location eq "global" && !recur_exists($self->{'cfg'}, 'snort', @var));

        if (recur_exists($self->{'cfg'}, 'snort', @var)) {
                return 1 if ($location eq "global");
                return "global" if ($location eq "first");
                push @$rv, "global";
        }

        return $rv;
}

=head2 $bool = $cfg-E<gt>snortEnabled(network)

Determines snort status on the specified network, returns either
enabled, disabled, or not_really on success, 0 on failure.

=cut

sub snortEnabled {
    my $self = shift;
    my $nw   = shift;

    $self->reloadIfChanged();

    my $s = $self->snort(-key => 'mode', -network => $nw);
    return 0 unless defined $s;

    return $s if ($s =~ /^(enabled|disabled|not_really)$/i);
    return 0;
}

=head2 $sensors = $cfg-E<gt>getSnortSensors(network)

Returns a HASHREF with hostname:port of the sensor being the keys and
the values either ro|rw representing whether sensor modification is
permitted or not. Returns C<undef> on failure.

=cut

sub getSnortSensors {
    my $self = shift;
    my $nw   = shift;
    my $sensors = {};

    $self->reloadIfChanged();
    return undef unless ($self->snortEnabled($nw) =~ /^(enabled|not_really)$/);

    my $s = $self->snort(-key => 'servers', -network => $nw);
    return undef if (!defined $s && ref($s) ne 'HASH');
   
    foreach (keys %$s) {
	my $v = $self->snort(-key => $_, -sval => 'servers', -network => $nw);
	$sensors->{$_} = ($v =~ /rw|ro/) ? $v : 'ro';
    } 

    return $sensors;
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

=head2 my $cmac = $cfg-E<gt>getCustomMAC(network)

return the custom MAC address we've set for this network.
See Appendix D of the NetPass manual for a discussion on how this is used.

=cut

sub getCustomMAC {
        my $self = shift;
        my $nw = shift;

	$self->reloadIfChanged();

        if ($self->{'cfg'}->obj('network')->exists($nw)) {
                if ($self->{'cfg'}->obj('network')->obj($nw)->exists('cmac')) {
                        return $self->{'cfg'}->obj('network')->obj($nw)->value('cmac');
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
switches (all switches in all networks, vlanmaps and community name sections).

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
	    @switches = ($self->{'cfg'}->keys('vlanmap'), $self->{'cfg'}->obj('snmpcommunities')->keys('host'));
	    foreach my $sw (@switches) {
		    $switches{$sw} = 1;
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

=head2 $cfg-E<gt>setNetwork(-network => '', -comment => '', -interface => '', -qvid => #, -uqvid => #, -cmac => '')

Given a network, set the various "core" network fields. A comment of "" or undef is OK. 'cmac'
is optional. All other fields are required.

RETURNS

0         on success
"..."     on failure

=cut


sub setNetwork {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-network -comment -interface -qvid -uqvid -cmac)],
				 -required => [qw(-network -interface -qvid -uqvid)],
				 -defaults => { -comment => '', -cmac => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters: ".Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($network, $comment, $interface, $qvid, $uqvid, $cmac) = 
	  $parms->get('-network', '-comment', '-interface', '-qvid', '-uqvid', '-cmac');

	$comment ||= '';
	$cmac    ||= '';

	if ($cmac ne '' && ($cmac !~ /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i) ) {
		return "invalid parameters: cmac does not look like a MAC address";
	}

	$self->reloadIfChanged();

	if( ! $self->{'cfg'}->obj('network')->exists($network) ) {
		$self->{'cfg'}->obj('network')->$network({});
	}

	_log("DEBUG", "set network comment $comment\n");
	_log("DEBUG", "set network int $interface\n");
	_log("DEBUG", "set network qid $qvid\n");
	_log("DEBUG", "set network nqid $uqvid\n");
	_log("DEBUG", "set network cmac $cmac\n");

	$self->{'cfg'}->obj('network')->obj($network)->comment($comment);
	$self->{'cfg'}->obj('network')->obj($network)->interface($interface);
	$self->{'cfg'}->obj('network')->obj($network)->quarantine($qvid);
	$self->{'cfg'}->obj('network')->obj($network)->nonquarantine($uqvid);

	$self->{'cfg'}->obj('network')->obj($network)->cmac($cmac) if ($cmac ne '');
	$self->{'cfg'}->obj('network')->obj($network)->delete('cmac') if ($cmac eq '');

	return 0;
}

=head2 $cfg-E<gt>delNetwork(-network => '')

Given a network, delete it from the config.

RETURNS

0                  on success
"no such network"  no such network
"..."              on failure

=cut


sub delNetwork {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-network)],
				 -required => [qw(-network)],
				 -defaults => { -network => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters: ".Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($network) = $parms->get('-network');

	$self->reloadIfChanged();

	if( $self->{'cfg'}->obj('network')->exists($network) ) {
		$self->{'cfg'}->obj('network')->delete($network);
		return 0;
	}

	return "no such network";
}

=head2 $cfg-E<gt>setHA(-network => '', -enabled => 0|1, -primary => '', -secondary => '', -virtualip => '', -servers => [])

Enable, disable and set High Availability related info. All parameters are required except for 'secondary'.

RETURNS

0                    on success
"invalid parameters" on failure
"no such network"    on failure

=cut


sub setHA {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-network -enabled -primary -secondary -virtualip -servers)],
				 -required => [qw(-network -enabled -primary -virtualip -servers)],
				 -defaults => { -secondary => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters: ".Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($network, $enabled, $primary, $secondary, $virtualip, $servers) = 
	  $parms->get('-network', '-enabled', '-primary', '-secondary', '-virtualip', '-servers');

	if ($enabled !~ /^[01]$/) {
		return "invalid parameters: enabled is not 0 or 1";
	}

	$secondary ||= '';

	$self->reloadIfChanged();

	if( ! $self->{'cfg'}->obj('network')->exists($network) ) {
		return "no such network";
	}

	if( ! $self->{'cfg'}->obj('network')->obj($network)->exists('ha') ) {
		$self->{'cfg'}->obj('network')->obj($network)->ha({});
	}


	$self->{'cfg'}->obj('network')->obj($network)->obj('ha')->status('enabled') if $enabled;
	$self->{'cfg'}->obj('network')->obj($network)->obj('ha')->status('disabled') if !$enabled;

	my $v = 'primary-redirector';
	$self->{'cfg'}->obj('network')->obj($network)->obj('ha')->$v($primary);
	   $v = 'secondary-redirector';
	$self->{'cfg'}->obj('network')->obj($network)->obj('ha')->$v($secondary);
	$self->{'cfg'}->obj('network')->obj($network)->obj('ha')->virtualip($virtualip);

	my %s;
	my $sa = [];
	if (ref($servers) eq "ARRAY") {
		$sa = $servers;
	} else {
		$sa = [ $servers ];
	}
	foreach my $s (@$sa) {
		$s{$s} = "";
	}
	$self->{'cfg'}->obj('network')->obj($network)->obj('ha')->servers(\%s);

	return 0;
}

=head2 $cfg-E<gt>setGarp(-network => '', -enabled => 0|1, -delay => 10, -number => 3)

Enable, disable and set Gratuitous Arp related info. Status and enabled are required. Delay and Number
are optional.

RETURNS

0                    on success
"invalid parameters" on failure
"no such network"    on failure

=cut


sub setGarp {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-network -enabled -delay -number)],
				 -required => [qw(-network -enabled)],
				 -defaults => { -delay => 10, -number => 3 }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters: ".Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($network, $enabled, $delay, $number) = 
	  $parms->get('-network', '-enabled', '-delay', '-number');

	if ($enabled !~ /^[01]$/) {
		return "invalid parameters: enabled is not 0 or 1";
	}

	if ($delay !~ /^\d+$/) {
		return "invalid parameters: delay is non-numeric";
	}

	if ($number !~ /^\d+$/) {
		return "invalid parameters: number is non-numeric";
	}

	$self->reloadIfChanged();

	if( ! $self->{'cfg'}->obj('network')->exists($network) ) {
		return "no such network";
	}

	if( ! $self->{'cfg'}->obj('network')->obj($network)->exists('garp') ) {
		$self->{'cfg'}->obj('network')->obj($network)->garp({});
	}

	$self->{'cfg'}->obj('network')->obj($network)->obj('garp')->status('enabled') if $enabled;
	$self->{'cfg'}->obj('network')->obj($network)->obj('garp')->status('disabled') if !$enabled;
	$self->{'cfg'}->obj('network')->obj($network)->obj('garp')->delay($delay);
	$self->{'cfg'}->obj('network')->obj($network)->obj('garp')->number($number);

	return 0;
}

=head2 $cfg-E<gt>setSwitches(-network => '', -switches => [], -bsw => '')

Set the list of switches that service this network. BSW is optional. If BSW has
user ports on it, it should be specified both in the switches list and as the
BSW parameter.

RETURNS

0                    on success
"invalid parameters" on failure
"no such network"    on failure

=cut


sub setSwitches {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-network -switches -bsw)],
				 -required => [qw(-network -switches)],
				 -defaults => { -bsw => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters: ".Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($network, $switches, $bsw) = 
	  $parms->get('-network', '-switches', '-bsw');

	$self->reloadIfChanged();

	if( ! $self->{'cfg'}->obj('network')->exists($network) ) {
		return "no such network";
	}

	if( ! $self->{'cfg'}->obj('network')->obj($network)->exists('switches') ) {
		$self->{'cfg'}->obj('network')->obj($network)->switches({});
	}

	my $sa = [];
	if (ref($switches) eq "ARRAY") {
		$sa = $switches;
	} else {
		$sa = [ $switches ];
	}
	my %s;
	foreach my $s (@$sa) {
		$s{$s} = '';
	}
	$self->{'cfg'}->obj('network')->obj($network)->switches(\%s);

	if ($bsw) {
		$self->{'cfg'}->obj('network')->obj($network)->obj('switches')->bsw($bsw);
	} else {
		$self->{'cfg'}->obj('network')->obj($network)->obj('switches')->delete('bsw');
	}

	return 0;
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

SETTING POLICY SETTINGS

=over 4

If a -val is given, the policy variable will be set instead of fetched. If no
network is specified, the global policy is set. If a network is specified, 
the specific policy for the network is set. If a groupname is given, the 
specific policy for that group is set.

=back

RETURN VALUES

=over 4

 value (even undef)  on successful fetch or set

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

	if (!defined($parms)) {
		_log("ERROR", Carp::longmess("invalid parameters ".Class::ParmList->error)."\n");
		return undef;
	}

	my ($pvar, $nw, $val) = $parms->get('-key', '-network', '-val');

	$nw = "" if ($nw eq "default");
	$nw ||= "";

	_log("DEBUG", "policy(-key $pvar, -network $nw)\n") if $self->debug;

	$self->reloadIfChanged();

	$pvar =~ tr [A-Z] [a-z]; # because of AutoLowerCase

	# if network looks like an IP, figure out which <network> clause
	# applies. else we assume network is a group name (if it's defined
	# at all)

	if ($nw =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) { 
		_log("DEBUG", "policy($pvar): resolve nw=$nw\n") if $self->debug;
		$nw = $self->getMatchingNetwork(-ip => $nw);
		_log("DEBUG", "policy($pvar): resolved to nw=$nw\n") if $self->debug;
	} 


	# this is a lookup operation

	if ( !defined($val) ) {
		# if the network has a <policy> section, check it for the given
		# pvar

		_log ("DEBUG", "this is a policy lookup (not set) for ".$pvar."\n") if $self->debug;

		if (recur_exists ($self->{'cfg'}, "network", $nw, "policy", $pvar)) {
			_log("DEBUG", "policy($pvar): nw=$nw has policy section. returning that.\n") if $self->debug;
			return  $self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->value($pvar);
		}


		# if the network has a group name, check the group

		my $netgroup = "";
		if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
			$netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
			_log("DEBUG", "policy($pvar): nw=$nw is member of group $netgroup\n") if $self->debug;
			$netgroup =~ s/\s/\%20/g; # Config::General bug workaround
                                                  # reported 3-may-2005 (see once more below!)
			$netgroup =~ tr [A-Z] [a-z]; # another Config::General bug
			                             # reported 3-may-2005

			if (recur_exists ($self->{'cfg'}, "group", $netgroup, "policy", $pvar)) {
				_log("DEBUG", "policy($pvar): (nw=$nw) group=$netgroup has policy section. returning that.\n") if $self->debug;
				return $self->{'cfg'}->obj('group')->obj($netgroup)->obj('policy')->value($pvar);
			}
		}

		# if the above didnt work, perhaps we were given a group name

		$netgroup = $nw;
		$netgroup =~ s/\s/\%20/g; # Config::General bug workaround
		$netgroup =~ tr [A-Z] [a-z]; # another Config::General bug
		if (recur_exists($self->{'cfg'}, "group", $netgroup)) { 
			_log ("DEBUG", "policy($pvar): (nw=$nw) looks like a netgroup.\n") if $self->debug;
			if (recur_exists($self->{'cfg'}, 'group', $netgroup, 'policy', $pvar)) {
				_log ("DEBUG", "policy($pvar): (nw=$nw) found it in netgroup policy\n") if $self->debug;
				return $self->{'cfg'}->obj('group')->obj($netgroup)->obj('policy')->value($pvar);
			}
		}

		# finally, look in the global policy

		_log("DEBUG", "policy($pvar): looking in global policy.\n") if $self->debug;
		
		return $self->{'cfg'}->obj('policy')->value($pvar) 
		  if (recur_exists ($self->{'cfg'}, "policy", $pvar));
		
		_log("DEBUG", "policy($pvar): no global policy. $pvar not found.\n") if $self->debug;

		return undef;
	} 

	# this is a set operation

	else {
		my $oldvalue = undef;

		_log ("DEBUG", "this is a policy set (not lookup) for ".$pvar." $val\n") if $self->debug;

		if ($nw =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/) { 
			# set the <network>'s policy

			_log("DEBUG", "nw=$nw examine network clause\n") if $self->debug;

			if (! recur_exists ($self->{'cfg'}, "network", $nw)) {
				_log("DEBUG", "nw=$nw no such network\n");
				return undef; #"nosuch network";
			}

			if (! recur_exists ($self->{'cfg'}, "network", $nw, "policy")) {
				# create one
				_log("DEBUG", "nw=$nw create network policy clause\n") if $self->debug;
				$self->{'cfg'}->obj('network')->obj($nw)->policy({});
			}

			if ( recur_exists ($self->{'cfg'}, "network", $nw, "policy", $pvar) ) {
				$oldvalue = $self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->value($pvar);
			}
			_log("DEBUG", "nw=$nw set network policy for $pvar\n") if $self->debug;
			$self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->$pvar($val);
			return $oldvalue;
		} 
		elsif ($nw ne "") {
			# set the <group> policy

			_log("DEBUG", "group=$nw set group policy for $pvar\n") if $self->debug;

			$nw =~ s/\s/\%20/g; # Config::General bug workaround
                                            # reported 3-may-2005
			$nw =~ tr [A-Z] [a-z]; # another Config::General bug

			if (! recur_exists ($self->{'cfg'}, "group", $nw)) {
				return undef; #"nosuch group";
			}

			if (! recur_exists ($self->{'cfg'}, "group", $nw, 'policy')) {
				# create one
				_log("DEBUG", "group=$nw create a group policy \n") if $self->debug;
				$self->{'cfg'}->obj('group')->obj($nw)->policy({});
			}

			if ( recur_exists ($self->{'cfg'}, "network", $nw, "policy", $pvar) ) {
				_log("DEBUG", "group=$nw set group policy for $pvar (has oldval)\n") if $self->debug;
				$oldvalue = $self->{'cfg'}->obj('group')->obj($nw)->obj('policy')->value($pvar);
				$self->{'cfg'}->obj('group')->obj($nw)->obj('policy')->$pvar($val);
				return $oldvalue;
			}

			_log("DEBUG", "group=$nw set group policy for $pvar (no oldval)\n") if $self->debug;
			$self->{'cfg'}->obj('group')->obj($nw)->obj('policy')->$pvar($val);
			return undef;

		}
		else {
			_log("DEBUG", "set global policy for $pvar\n") if $self->debug;
			if (! recur_exists($self->{'cfg'}, "policy") ) {
				_log("DEBUG", "create global policy\n") if $self->debug;
				# create one
				$self->{'cfg'}->policy({});
			}

			if (recur_exists ($self->{'cfg'}, "policy", $pvar) ) {
				_log("DEBUG", "set global policy (fetch oldval) $pvar \n") if $self->debug;
				$oldvalue = $self->{'cfg'}->obj('policy')->value($pvar);
			}
			_log("DEBUG", "set global policy $pvar\n") if $self->debug;
			$self->{'cfg'}->obj('policy')->$pvar($val);
			return $oldvalue;
		}

	}

	return undef;
}


=head2 policyLocation(-key => '', -network => '', -location => [''|first|global|group|network])

Check if a given policy variable is set in the specified location. If location
is '', then we return an ARRAY ref that contains the locations the given
variable was found in. Otherwise we return 0 or 1 based on whether or not
we found the variable in the specified location.

If "first" is given as the location, then we'll start at the most specific scope possible
and work towards the most general scope. The first time we see the variable, we'll
return the scope that we are at.

RETURNS

  0                     not found in specified location
  1                     found in specified location
  "network"             found here "first"
  "group"               found here "first"
  "global"              found here "first"
  ARRAYREF              found in the following locations (may be empty)
  "invalid parameters"  routine called incorrectly

=cut

sub policyLocation {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-key -network -location)],
				 -required => [qw(-key)],
				 -defaults => { -network => '', -location => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters ". Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($pvar, $nwOrig, $location) = $parms->get('-key', '-network', '-location');

	_log("DEBUG", "checking for policy $nwOrig:$pvar in location:$location\n") if $self->debug;

	$pvar =~ tr [A-Z] [a-z]; # AutoLowerCase
        $nwOrig = "" if ($nwOrig eq "default");

        my $rv = [];

	my $nw = $self->getMatchingNetwork(-ip => $nwOrig);

	if ($nw && ($nw ne "none")) {
		return 0 
		  if ($location eq "network" && !recur_exists($self->{'cfg'}, 'network', 
							      $nw, 'policy', $pvar));
		
		if (recur_exists($self->{'cfg'}, 'network', $nw, 'policy', $pvar)) {
			return 1 if ($location eq "network");
			return "network" if ($location eq "first");
			push @$rv, "network";
		}

		# if this network is part of a netgroup, check there too

		my $ng = $self->getNetgroup(-network => $nw);
		if ($ng) {
			$ng =~ s/\s/%20/g;
			$ng =~ tr [A-Z] [a-z];
			push @$rv, "group"
			  if (recur_exists($self->{'cfg'}, 'group', $ng, 'policy', $pvar));
		}
	}
	else {
		# perhaps this is a netgroup?
		my $nw2 = $nwOrig;
		$nw2 =~ s/\s/%20/g; # Config::General bug
		$nw2 =~ tr [A-Z] [a-z]; # Config::General bug

		if (($location eq "group") && !recur_exists($self->{'cfg'}, 'group',
							    $nw2, 'policy', $pvar)) {
			return 0;
		}

		if (recur_exists($self->{'cfg'}, 'group', $nw2, 'policy', $pvar)) {
			return 1 if ($location eq "group");
			return "group" if ($location eq "first");
			push @$rv, "group";
		}
	}


	return 0 
	  if ($location eq "global" && !recur_exists($self->{'cfg'}, 'policy', $pvar));

        if (recur_exists($self->{'cfg'}, 'policy', $pvar)) {
                return 1 if ($location eq "global");
		return "global" if ($location eq "first");
                push @$rv, "global";
        }

	return $rv;
}

=head2 removePolicy(-key => '', -network => '', -location => [global|group|network])

Remove the policy variable from the specified location. You can't remove
policy variables from the "global" location, despite being listed.

RETURNS

  0                     success
  "invalid parameters"  routine called incorrectly
  "cant remove"         cant remove the variable

=cut

sub removePolicy {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-key -network -location)],
				 -required => [qw(-key)],
				 -defaults => { -network => '', -location => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters ".Carp::longmess("invalid parameters ".Class::ParmList->error);
	}

	my ($pvar, $nw, $location) = $parms->get('-key', '-network', '-location');

	$pvar =~ tr [A-Z] [a-z]; # AutoLowerCase
        $nw = "" if ($nw eq "default");

        if ( ($location eq "global") && recur_exists($self->{'cfg'}, 'policy', $pvar)) {
		# global policy settings cant be deleted.
		return "cant remove global policy variable";
        }

	my $nw2 = $nw;
	$nw2 =~ s/\s/%20/g; # Config::General bug
	$nw2 =~ tr [A-Z] [a-z]; # Config::General bug

	if (($location eq "group") && recur_exists($self->{'cfg'}, 'group', $nw2, 'policy', $pvar)) {
		$self->{'cfg'}->obj('group')->obj($nw2)->obj('policy')->delete($pvar);
		return 0;
	}

	$nw = $self->getMatchingNetwork(-ip => $nw);

        return 0 if $nw eq "none";

	if ( ($location eq "network") && 
	     recur_exists($self->{'cfg'}, 'network', $nw, 'policy', $pvar)) {
		$self->{'cfg'}->obj('network')->obj($nw)->obj('policy')->delete($pvar);
		return 0;
	}

	return 0;
}

=head2 0|1 = $cfg-E<gt>createNetgroup(-name => $name)

Create a new netgroup.

RETURNS
 0                    on success
 "group exists"       on failure (group already exists)
 "invalid parameters" routine called improperly

=cut

sub createNetgroup {
    my $self = shift;

    $self->reloadIfChanged();

    my $parms = parse_parms({
			     -parms    => \@_,
			     -legal    => [qw(-name)],
			     -required => [qw(-name)],
			     -defaults => { -name => '' }
			    }
			   );

    return Carp::longmess("invalid parameters ".Class::ParmList->error) if (!defined($parms));
    
    my ($name) = $parms->get('-name');
    my $oname = $name;

    return "invalid parameters" if (!defined($name) || ($name eq ""));

    $name =~ s/\s/%20/g;  # Config::General bug
    $name =~ tr [A-Z] [a-z]; # another Config::General bug

    if (recur_exists($self->{'cfg'}, "group", $name)) {
	    return "group exists";
    }
    $self->{'cfg'}->obj("group")->$name({'name' => $oname}); # damn C::G
    return 0;
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

	    if ($ip =~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$/) { # looks like a network already
		    if (recur_exists($self->{'cfg'}, "network", $ip)) {
			    return $ip;
		    } else {
			    return "none";
		    }
	    }

            # doesnt look like an IP.

	    if ($ip !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
                   return "none";
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


=head2 getNetgroup(-network => '')

Return the netgroup that the given network is a member of. If -network is an 
IP address, we'll resolve it first to a network.

RETURNS

 groupname            on success
 ''                   if not a member of anygroup

=cut

sub getNetgroup {
	my $self    = shift;

	$self->reloadIfChanged();

	my $parms = parse_parms({
				 -parms    => \@_,
				 -legal    => [qw(-network)],
				 -required => [qw(-network)],
				 -defaults => { -network => '' }
				}
			       );
	
	if (!defined($parms)) {
		warn Carp::longmess("invalid parameters ".Class::ParmList->error);
		return undef;
	}
	
	my ($network) = $parms->get('-network');

	my $nw = $self->getMatchingNetwork(-ip => $network);
	my $netgroup = '';

	if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
		$netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
	}

	return $netgroup;
}

=head2 getNetgroupMembers(-group => '')

Return an arrayref of all members of the given netgroup.

RETURNS

 ARRAYREF             on success
 'invalid parameters' improperly called

=cut

sub getNetgroupMembers {
	my $self    = shift;

	$self->reloadIfChanged();

	my $parms = parse_parms({
				 -parms    => \@_,
				 -legal    => [qw(-group)],
				 -required => [qw(-group)],
				 -defaults => { -group => '' }
				}
			       );
	
	if (!defined($parms)) {
		return Carp::longmess("invalid parameters ".Class::ParmList->error);
	}
	
	my ($group) = $parms->get('-group');

	my $allnw = $self->getNetworks();
        my @members = ();
        if (ref($allnw) eq "ARRAY") {
                foreach my $nw (@$allnw) {
	                if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
		                my $netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
                                if ($netgroup eq $group) {
                                        push @members, $nw;
                                }
                        }
                }
	}

	return \@members;
}

=head2 getNetgroups()

Return an arrayref of all netgroups.

RETURNS

 ARRAYREF             on success
 'invalid parameters' improperly called

=cut

sub getNetgroups {
	my $self    = shift;

	$self->reloadIfChanged();

        my @ngs = ();

	foreach my $ng ($self->{'cfg'}->keys('group')) {
		push @ngs, $self->{'cfg'}->obj('group')->obj($ng)->value('name')
		  if recur_exists($self->{'cfg'}, 'group', $ng, 'name');
	}
	return \@ngs;
}

=head2 delNetgroup(-group => '')

Delete the given netgroup. Any networks in the netgroup will have their
membership removed but will otherwise be unchanged.

RETURNS

 0                    on success
 'invalid parameters' improperly called

=cut

sub delNetgroup {
	my $self    = shift;

	$self->reloadIfChanged();

	my $parms = parse_parms({
				 -parms    => \@_,
				 -legal    => [qw(-group)],
				 -required => [qw(-group)],
				 -defaults => { -group => '' }
				}
			       );
	
	if (!defined($parms)) {
		return Carp::longmess("invalid parameters ".Class::ParmList->error);
	}
	
	my ($group) = $parms->get('-group');

	my $g2 = $group;
	$g2 =~ s/\s/%20/g;
	$g2 =~ tr [A-Z] [a-z];

        if (recur_exists($self->{'cfg'}, 'group', $g2)) {
		_log("DEBUG", "remove $g2\n");
                $self->{'cfg'}->obj('group')->delete($g2);
        }

	my $allnw = $self->getNetworks();
        if (ref($allnw) eq "ARRAY") {
                foreach my $nw (@$allnw) {
	                if (recur_exists ($self->{'cfg'}, "network", $nw, "group")) {
		                my $netgroup =  $self->{'cfg'}->obj('network')->obj($nw)->value('group');
                                if ($netgroup eq $group) {
                                        $self->{'cfg'}->obj('network')->obj($nw)->delete('group');
                                }
                        }
                }
	}

	return 0;
}

=head2 setNetgroup(-network => '', -group => '')

Placed the specified network into the specified group. A network can only be 
a member of one group. If -group is not specified, the network is removed
from any group it is it. If -group is specified and the network is already 
part of a group, it is removed from that group and placed into the one you
specified.

RETURNS

 0                    on success
 "no such network"    given network doesnt exist
 "invalid parameters" routine called incorrectly

=cut

sub setNetgroup {
	my $self = shift;
	$self->reloadIfChanged();

	my $parms = parse_parms({
				 -parms    => \@_,
				 -legal    => [qw(-network -group)],
				 -required => [qw(-network)],
				 -defaults => { -network => '', -group => '' }
				}
			       );
	
	return Carp::longmess("invalid parameters ".Class::ParmList->error) if (!defined($parms));
	
	my ($network, $netgroup) = $parms->get('-network', '-group');

	if (!recur_exists($self->{'cfg'}, 'network', $network)) {
		return "no such network";
	}

	if ($netgroup eq "") {
		# delete from group
		$self->{'cfg'}->obj('network')->obj($network)->delete('group');
	} else {
		# set the group
		$self->{'cfg'}->obj('network')->obj($network)->group($netgroup);
	}
	return 0;
}

=head2 $cfg-E<gt>setCommunities(-switch => '', -readonly => '', -readwrite => '')

Set the readonly and readwrite community names to use when
accessing the specified switch. Switch may be a network, in CIDR 
notation. Setting readonly and readwrite to '' causes the switch to 
be deleted from the communities section of the config (but not from
the 'network' section or 'vlanmap' section)

RETURNS

 0                    on success
 "invalid parameters" on failure
 "..."                on failure

=cut

sub setCommunities {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-switch) ],
			     -defaults => {
					   -switch    => '',
					   -readonly  => '',
					   -readwrite => ''
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($sw, $ro, $rw) = $parms->get('-switch', '-readonly', '-readwrite');

    if ($sw =~ /\/\d{1,2}$/) {
	    # looks like CIDR
	    if (!recur_exists($self->{'cfg'}, "snmpcommunities", "network")) {
		    $self->{'cfg'}->obj("snmpcommunities")->network({});
	    }
	    if (!recur_exists($self->{'cfg'}, "snmpcommunities", 'network', $sw)) {
		    $self->{'cfg'}->obj('snmpcommunities')->obj('network')->$sw({});
	    }

	    if ($ro eq "" && $rw eq "") {
		    $self->{'cfg'}->obj('snmpcommunities')->obj('network')->delete($sw);
	    } else {
		    $self->{'cfg'}->obj('snmpcommunities')->obj('network')->$sw({'read' => $ro,
										 'write' => $rw});
	    }
	    return 0;
    }

    if (!recur_exists($self->{'cfg'}, "snmpcommunities", 'host')) {
	    $self->{'cfg'}->obj('snmpcommunities')->host({});
    }

    if (!recur_exists($self->{'cfg'}, "snmpcommunities", 'host', $sw)) {
	    $self->{'cfg'}->obj('snmpcommunities')->obj('host')->$sw({});
    }

    if ($ro eq "" && $rw eq "") {
	    _log("DEBUG", "ro/rw empty. del $sw\n");
	    $self->{'cfg'}->obj('snmpcommunities')->obj('host')->delete($sw);
    } else {
	    $self->{'cfg'}->obj('snmpcommunities')->obj('host')->$sw({'read' => $ro,
								      'write' => $rw});
    }

    return 0;
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


=head2 my @tagList = $cfg-E<gt>availableVlans(-switch => IP, -port => port)

=head2 my @tagList = $cfg-E<gt>availableVlans(-network => network)

Given a hostname (or IP) and a port, return the list of available tags
for that port. This list will always be two elements. The first is the 
"unquarantine" vlan and the second is the "quarantine" vlan. 

RETURNS

=over 4

=item ($unquar_vlanid, $quar_vlanid)

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

=head2 $encodedTagList = encodeTagList($tlHref)

This routine is not a method. Given a tagList hash ref such as

    $tl->{'12/812'} = [ 1,2,3,5,6 ];
    $tl->{'13/813'} = [ 10,11,12,20,21 ];

encode it into the format:

    port1,port3-port5:good/bad;port7-port10:good/bad

See also: expandTagList()

Returns
   "..."                encoded tag list
   "invalid parameters" routine called improperly

=cut

sub encodeTagList {
	my $th = shift;
	if (ref($th) ne "HASH") {
		return "invalid parameters";
	}

	my $v = {};
	foreach my $port (keys %$th) {
		my $val = $th->{$port};
		$val =~ s/\|/\//g;
		if ( exists $v->{$val} ) {
			$v->{$val} = [ $port ];
		} 
		else {
			push @{$v->{$val}}, $port;
		}
	}

	# now we have th->{'12/812'} = [ 1,2,3,6,7,8 ]
	# and we want to go to
	# th->{'12/812'} = '1-3,6-8'

	foreach my $vlan (keys %$th) {
		$th->{$vlan} = formatPorts($th->{$vlan});
	}
	
	
}

sub formatPorts {
        my $d   = shift;
        my $s = "";

        foreach my $vid (keys %$d) {
                my @t = sort {$a<=>$b} @{$d->{$vid}};

                my $start = $t[0];
                my $prev  = $start;
                my $cur   = $start;

                my @myline;

                for (my $i = 1 ; $i <= $#t ; $i++) {
                        $cur = $t[$i];
                        if ($cur - $prev > 1) {
                                # we've hit a break
                                if ($start != $prev) {
                                        push @myline, "$start-$prev";
                                } else {
                                        push @myline, "$start";
                                }
                                $prev = $start = $cur ;
                        } else {
                                $prev = $cur;
                        }
                }

                if ($start != $prev) {
                        push @myline, "$start-$prev";
                } else {
                        push @myline, "$start";
                }

                $s .= join(',', @myline).':'.$vid.';';
        }
        return $s;
}


=head2 $vlanmap = getVlanMap($switch)

Retrieve an encoded vlanmap.

RETURNS 
  scalar on success
  undef  on failure (or switch doesnt exist)

=cut

sub getVlanMap {
	my $self = shift;
	my $sw   = shift;

	$sw ||= '';
	if (recur_exists($self->{'cfg'}, 'vlanmap', $sw)) {
		return $self->{'cfg'}->obj('vlanmap')->value($sw);
	}
	return undef;
}

=head2 (void) setVlanMap($switch, $vlanmap)

Pass in an encoded vlanmap. If vlanmap is "" then it deletes
the switch from the vlanmap portion of the config.

RETURNS
   nothing useful

=cut

sub setVlanMap {
	my $self = shift;
	my $sw   = shift;
	my $vm   = shift;

	$sw ||= '';
	$vm ||= '';
	if ($vm ne "") {
		$self->{'cfg'}->obj('vlanmap')->$sw($vm);
	} else {
		$self->{'cfg'}->obj('vlanmap')->delete($sw);
	}
	return undef;
}

=head2 $tlHref = expandTagList($encodedTagList)

This routine is not a method. Given an encoded tag list (vlanmap) like


 tagList format:
    port1,port3-port5:good/bad;port7-port10:good/bad

 e.g. if the switch services multiple networks (2 in this case)

   1,10-20:12/812;2-9,21-24:13/813

 or more simply, you'll typically have:

   1-24:12/812

 where '12' is the 'good/normal' vlan and '812' is the quarantine

Return a hash ref with the port as the key and the vlan as the value. 
So, for example, you'll have: $tl->{10} = '12|812'. For historical
reasons the "/" is converted to "|". 

=cut

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

=head2 B<$np->cfg->nessus(-key => key, -val => val)>

Given a <nessus> config variable, return the value. If -val is given,
the set the value.

RETURNS

=over 4

 value or undef    on success

=back

=cut

sub nessus {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-key -network -val)],
				 -required => [qw(-key)],
				 -defaults => { -network => '', -val => undef }
			    }
			   );

	if (!defined($parms)) {
		warn Carp::longmess("invalid parameters ".Class::ParmList->error);
		return undef;
	}

	my ($key, $nw, $val) = $parms->get('-key', '-network', '-val');

	$key =~ tr [A-Z] [a-z];

	$self->reloadIfChanged();

	if (defined($val)) {
		my $oldval = undef;
		$self->{'cfg'}->nessus({}) if (! $self->{'cfg'}->exists('nessus') );
		$oldval = ($self->{'cfg'}->obj('nessus')->exists($key)) 
		  if ($self->{'cfg'}->obj('nessus')->exists($key));
		$self->{'cfg'}->obj('nessus')->$key($val);
		return $oldval;
	}

	return $self->{'cfg'}->obj('nessus')->value($key)
	  if (recur_exists($self->{'cfg'}, 'nessus', $key));
	return undef;
}

=head2 getLDAP($server)

If server is "" it returns an array ref of all configured
LDAP servers (in hostname[:port] notation). If server is
formatted as "hostname[:port]" it will return a hashref containing
the keys:

 base           the search base
 filter         the filter to use
 passwordfield  the name of the password field

RETURNS
 arrayref     on success
 hashref      on success
 undef        on failure or no-such-server

=cut

sub getLDAP {
	my $self = shift;
	my $s = shift;
	$s ||= "";
	if (recur_exists($self->{'cfg'}, "ldap", $s)) {
		return { 'base'          => $self->{'cfg'}->obj('ldap')->obj($s)->value('base'),
			 'filter'        => $self->{'cfg'}->obj('ldap')->obj($s)->value('filter'),
			 'passwordField' => $self->{'cfg'}->obj('ldap')->obj($s)->value('passwordfield'),
		       };
	}
	elsif (recur_exists($self->{'cfg'}, "ldap")) {
		return [ $self->{'cfg'}->keys('ldap') ];
	}
	return undef;
}


=head2 setLDAP(-server => '', -base => '', -filter => '', -passwordField => '');

If all params (except server) are '' then the server is deleted. 
Server can be either a hostname, ip address or either of those 
followed by ":port".

RETURNS
 0                    on success
 "invalid parameters" routine called improperly

=cut

sub setLDAP {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-server -base -filter -passwordField)],
				 -required => [qw(-server)],
				 -defaults => { -server        => '',
						-filter        => '',
						-base          => '',
						-passwordField => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters ".Carp::longmess(Class::ParmList->error);
	}

	my ($server, $base, $filter, $pfield) = 
	  $parms->get('-server', '-base', '-filter', '-passwordField');

	if (!recur_exists($self->{'cfg'}, 'ldap', $server)) {
		$self->{'cfg'}->obj('ldap')->$server({});
	}
	if ($base.$filter.$pfield ne "") {
		$self->{'cfg'}->obj('ldap')->obj($server)->base($base)
		  if ($base);
		$self->{'cfg'}->obj('ldap')->obj($server)->filter($filter)
		  if ($filter);
		$self->{'cfg'}->obj('ldap')->obj($server)->passwordfield($pfield)
		  if ($pfield);
	} 
	else {
		$self->{'cfg'}->obj('ldap')->delete($server);
	}
	return 0;
}

=head2 getRadius($server)

If server is "" it returns an array ref of all configured
radius servers (in hostname:port notation). If server is
formatted as "hostname:port" it will return a hashref containing
the keys:

 secret       the secret to use

RETURNS
 arrayref     on success
 hashref      on success
 undef        on failure or no-such-server

=cut

sub getRadius {
	my $self = shift;
	my $s = shift;
	$s ||= "";
	if (recur_exists($self->{'cfg'}, "radius", $s)) {
		return { 'secret',
			 $self->{'cfg'}->obj('radius')->obj($s)->value('secret')
		       };
	}
	elsif (recur_exists($self->{'cfg'}, "radius")) {
		return [ $self->{'cfg'}->keys('radius') ];
	}
	return undef;
}

=head2 setRadius(-server => '', -secret => '');

If secret is '' then the server is deleted. Server can be either a
hostname, ip address or either of those followed by ":port".

RETURNS
 0                    on success
 "invalid parameters" routine called improperly

=cut

sub setRadius {
	my $self = shift;

        my $parms = parse_parms({
				 -parms => \@_,
				 -legal => [qw(-server -secret)],
				 -required => [qw(-server)],
				 -defaults => { -server => '', -secret => '' }
			    }
			   );

	if (!defined($parms)) {
		return "invalid parameters ".Carp::longmess(Class::ParmList->error);
	}

	my ($server, $secret) = $parms->get('-server', '-secret');

	if (!recur_exists($self->{'cfg'}, 'radius', $server)) {
		$self->{'cfg'}->obj('radius')->$server({});
	}
	if ($secret ne "") {
		$self->{'cfg'}->obj('radius')->obj($server)->secret($secret);
	} 
	else {
		$self->{'cfg'}->obj('radius')->delete($server);
	}
	return 0;
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

$Id: Config.pm,v 1.56 2006/03/23 18:50:04 jeffmurphy Exp $

=cut

1;
