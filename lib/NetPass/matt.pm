
package NetPass::Config;
use strict;

require Carp;
require Config::General;

use Data::Dumper;
use FileHandle;
use Net::DNS;
use NetPass::LOG qw(_log _cont);
use Class::ParmList qw(simple_parms parse_parms);

my $VERSION       	= '0.01';

=head1 NAME

NetPass::Config - NetPass Configuration File Interface

=head1 SYNOPSIS

    use NetPass::Config;

    $c = new NetPass::Config("/etc/netpass.conf")
    die "Cannot load netpass.conf: ". $c->error()
        if ($c->err);

=head1 DESCRIPTION

This object provides access to the NetPass configuration file. The configuration
file tracks things such as:

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

=head2 my $cfg = new NetPass::Config($configFile)

Create a new NetPass configuration object. The specified file
will be read in and you can then use this object's methods to
access the configuration attributes.

=cut

#tie $NetPass::Config::errstr, 'NetPass::Config::var', '&errstr'; 

my $errstr;

sub AUTOLOAD {
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
    $self->{'dbg'} = $val;
}

sub new {
  my ($class, $self) = (shift, {});
  my $cf = shift;

  die Carp::longmess("no configuration file specified") unless defined($cf);
  die Carp::longmess("configuration file doesn't exist ($cf)") unless (-f $cf && -r $cf);

  my $cfg =  new Config::General(-ConfigFile => $cf,
				 -AutoTrue => 1,
				 -ExtendedAccess => 1, 
				 -StrictObjects => 0);

  die Carp::longmess("failed to load configuration from $cf") unless defined($cfg);
  $self->{'cfg'} = $cfg;
  $self->{'dbg'} = 0;

  #$NetPass::Config::errstr = "nosuch";

  return bless ($self, $class);
}

=head2 my $dbh = $cfg-E<gt>dbSource

Return the database source appropriate for passing into DBI.

=cut

sub dbSource {
    my $self = shift;
    return $self->{'cfg'}->obj('database')->value('source');
}

=head2 my $dbuser = $cfg-E<gt>dbUser

Return the database username appropriate for passing into DBI.

=cut

sub dbUsername {
    my $self = shift;
    return $self->{'cfg'}->obj('database')->value('username');
}


=head2 my $dbpass = $cfg-E<gt>dbPassword

Return the database password appropriate for passing into DBI.

=cut

sub dbPassword {
    my $self = shift;
    return $self->{'cfg'}->obj('database')->value('password');
}

=head2 my $networks = $cfg-E<gt>getNetworks()

Return the list of defined E<lt>networkE<gt>'s. Returns an ARRAY REF on success,
C<undef> on failure.

=cut

sub getNetworks {
    my $self = shift; 
    return [ $self->{'cfg'}->keys('network') ];
}


=head2 my $int = $cfg-E<gt>getInterface(network)

return the interface that is connected to the given network. returns undef 
if the network is unknown.

=cut

sub getInterface {
	my $self = shift;
	my $nw = shift;
	if ($self->{'cfg'}->obj('network')->exists($nw)) {
		if ($self->{'cfg'}->obj('network')->obj($nw)->exists('interface')) {
			return $self->{'cfg'}->obj('network')->obj($nw)->value('interface');
		}
	}
	return undef;
}
=head2 my $switches = $cfg-E<gt>getSwitches(network)

Return the list of switches defined for this E<lt>networkE<gt>. Returns an ARRAY REF
on success, C<undef> on failure.

=cut


sub getSwitches {
    my ($self, $network) = (shift, shift);
    return [ $self->{'cfg'}->obj('network')->obj($network)->keys('switches') ];
}


=head2 $val = $np->policy($key)

Given a key (a policy/configuration variable name) return the associated value
or undef if the variable doesnt exist in the C<netpass.conf> file's 
E<lt>policyE<gt> section.

=cut

sub policy {
    my $self = shift;

    return undef 
      if (! exists $self->{'cfg'}) || 
	    (ref $self->{'cfg'} ne "Config::General::Extended");
    return undef if ! $self->{'cfg'}->exists('policy');

    my $k = shift;
    return undef unless defined $k;

    return undef if ! $self->{'cfg'}->obj('policy')->exists($k);
    return $self->{'cfg'}->obj('policy')->value($k);
}

=head2 my $network = $cfg-E<gt>getMatchingNetwork($ip)

Return the network that the specified IP is a part of. C<undef> if no such
network configured.

=cut

sub getMatchingNetwork {
    my $self = shift;
    my $ip   = shift;

## SELF_D

    my $ip_ = ip2int(host2addr($ip));

    foreach my $n ($self->{'cfg'}->keys('network')) {
	_log "DEBUG", "n=$n\n";
	my ($n_, $m_) = cidr2int($n);
	_log "DEBUG", sprintf("%x & %x ? %x (%x)\n", $ip_, $m_, $n_,
			     ($ip_ & $m_));
	return $n if ( ($ip_ & $m_) == $n_);
    }
    _log "DEBUG", "notfound\n";
    return undef;
}

=head2 my ($r, $w) = $cfg-E<gt>getCommunities(hostname)

Given a hostname (or IP address) lookup return the
SNMP read and write community names.

=cut

sub getCommunities {
  my $self = shift;
  my $hn   = shift;

  _log "DEBUG", "$hn\n";
  my $a    = host2addr($hn);
 
  # first check for a specific <host *> record

  my $nw = undef;

  if( exists $self->{'cfg'}->{'snmpcommunities'}->{'host'}->{$hn} ) {
    _log "DEBUG", "found exact host match for $hn\n" if $self->{'dbg'};
  } else {
    _log "DEBUG", "no exact host match ($hn)\n" if $self->{'dbg'};
    
    # using the address, see if we have an exact host match

    if( exists $self->{'cfg'}->{'snmpcommunities'}->{'host'}->{$a} ) {
      _log "DEBUG", "found exact host match for $a\n" if $self->{'dbg'};
    } else {
      _log "DEBUG", "no exact host match ($a)\n" if $self->{'dbg'};

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
      } else {
	_log "DEBUG", "no matching network for $a\n" if $self->{'dbg'};
	return (undef, undef);
      }

    } # exists host->addr

  } # exists host->hn

  return ($self->{'cfg'}->obj('snmpcommunities')->obj('network')->obj($nw)->read,
	  $self->{'cfg'}->obj('snmpcommunities')->obj('network')->obj($nw)->write);
}

=head2 my $ports = $cfg-E<gt>configuredPorts(host)

Given a hostname/IP of a switch return the list of ports we're configured to manage
on that switch. Returns an ARRAY REF on success, C<undef> on failure.

=cut

sub configuredPorts {
    my $self = shift;
    my $h = shift;

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

=head2 my $qvlan = $cfg-E<gt>quarantineVlan(network)

return the id of the quarantined vlan. returns undef if the
id or network is unknown.

=cut

sub quarantineVlan {
        my $self = shift;
        my $nw = shift;
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
        if ($self->{'cfg'}->obj('network')->exists($nw)) {
                if ($self->{'cfg'}->obj('network')->obj($nw)->exists('nonquarantine')) {
                        return $self->{'cfg'}->obj('network')->obj($nw)->value('nonquarantine');
                }
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

  my $parms = parse_parms({
			   -parms => \@_,
			   -legal => [qw(-switch -port -interface -vlan)]
			  }
			 );
  die Carp::longmess("availableVlans: ".Class::ParmList->error) if (!defined($parms));

  my ($h, $p, $if, $vid) = $parms->get('-switch', '-port', '-interface', '-vlan');

  my $av;
  if (defined($if)) {
      return $self->availableVlans_interface_and_vlan($if, $vid);
  }
  else {
      $av = $self->availableVlansRE_switch_and_port($h, $p);
  }

  return undef if !defined($av);
  return split(/\|/, $av);
}


sub availableVlans_interface_and_vlan {
  my $self      = shift;
  my $interface = shift;
  my $vid       = shift;

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

  my $a    = host2addr($h);

  # first, determine if we have a mapping for the specified hostname

  _log "DEBUG", "try to match VLANMAP by hostname\n" if $self->{'dbg'};

  if ($self->{'cfg'}->obj('vlanmap')->exists($h)) {
      _log "DEBUG", "matched.\n" if $self->{'dbg'};
      my $tagList = expandTagList($self->{'cfg'}->obj('vlanmap')->value($h));
      return $tagList->{$p} if (exists $tagList->{$p});
      return undef;
  }

  # otherwise, see if we can match on the IP

  else {
      _log "DEBUG", "try to match VLANMAP by IP\n" if $self->{'dbg'};

      if ($self->{'cfg'}->obj('vlanmap')->exists($a)) {
	  _log "DEBUG", "matched.\n" if $self->{'dbg'};
	  my $tagList = expandTagList($self->{'cfg'}->obj('vlanmap')->value($a));
	  return $tagList->{$p} if (exists $tagList->{$p});
	  return undef;
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
    return $tagList->{$p} if (exists $tagList->{$p});
  } else {
      _log "DEBUG", "no matching network for $a\n" if $self->{'dbg'};
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
  my $tl = shift;
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

=head2 $np->cfg->nessusHost()

=cut

=head2 $np->cfg->nessusPort()

=cut

=head2 $np->cfg->nessusUsername()

=cut

=head2 $np->cfg->nessusPassword()


=cut

sub nessusUsername {
    my $self = shift;
    return $self->{'cfg'}->obj('nessus')->value('username');
}

sub nessusPassword {
    my $self = shift;
    return $self->{'cfg'}->obj('nessus')->value('password');
}

sub nessusHost {
    my $self = shift;
    return $self->{'cfg'}->obj('nessus')->value('host');
}

sub nessusPort {
    my $self = shift;
    return $self->{'cfg'}->obj('nessus')->value('port');
}

sub nessusConfig {
    my $self = shift;

    return ($self->{'cfg'}->obj('nessus')->value('host'),
	    $self->{'cfg'}->obj('nessus')->value('username'),
	    $self->{'cfg'}->obj('nessus')->value('password'));
}

# for speedy lookups

my @cidr_to_int = (
0x00000000, #/0
0x80000000, #/1
0xc0000000, #/2
0xe0000000, #/3
0xf0000000, #/4
0xf8000000, #/5
0xfc000000, #/6
0xfe000000, #/7
0xff000000, #/8
0xff800000, #/9
0xffc00000, #/10
0xffe00000, #/11
0xfff00000, #/12
0xfff80000, #/13
0xfffc0000, #/14
0xfffe0000, #/15
0xffff0000, #/16
0xffff8000, #/17
0xffffc000, #/18
0xffffe000, #/19
0xfffff000, #/20
0xfffff800, #/21
0xfffffc00, #/22
0xfffffe00, #/23
0xffffff00, #/24
0xffffff80, #/25
0xffffffc0, #/26
0xffffffe0, #/27
0xfffffff0, #/28
0xfffffff8, #/29
0xfffffffc, #/30
0xfffffffe, #/31
0xffffffff  #/32
);


sub cidr2int {
  my $c = shift;

  $c .= "/32" unless ($c =~ /\/\d+/);

  if($c !~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d+)$/) {
    die Carp::longmess("cidr2int: \"$c\" doesnt look like a.b.c.d/f");
  }

  my $i   = ip2int($1);
  my $cbf = $2;
  my $m;

  # for the mask, did they give us, eg "/24" or did they 
  # give us "/255.255.255.0" ?

  if ($cbf =~ /^\d+$/) { # /24
    die Carp::longmess("cidr bit field must be between 1 and 32") 
    if ( $cbf < 1 || $cbf > 32 );
    $m = $cidr_to_int[$cbf];
  } else { #/255.255.255.0
    $m = ip2int($cbf);
  }

  return($i, $m);
}

sub ip2int {
  my $i = shift;

  if ($i !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
    die Carp::longmess("ip2int: \"$i\" doesnt look like an ip address to me");
  }

  my @o = split(/\./, $i);
  return ( ($o[0] << 24) |
	   ($o[1] << 16) | 
	   ($o[2] <<  8) |
	   ($o[3]      ) );
}

sub host2addr {
  my $hn    = shift;
  my $res   = new Net::DNS::Resolver;
  my $query = $res->search($hn);

  return $hn if ($hn =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);

  my $addr;


  if ($query) {
    foreach my $rr ($query->answer) {
      next unless $rr->type eq "A";
      return $rr->address;
      last;
    }
  } else {
    die Carp::longmess("cant resolve hostname ($hn) to an address: " .
		       $res->errorstring);
  }
  #notreached
}

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 CREDITS

This module uses L<Config::General> to do all the parsing of the 
configuration file.

$Header: /tmp/netpass/NetPass/lib/NetPass/Attic/matt.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

=cut

1;
