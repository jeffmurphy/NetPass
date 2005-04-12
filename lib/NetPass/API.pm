package NetPass::API;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw("/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use Digest::MD5 qw(md5_hex);

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

=head2 $aref = getSnortRules($secret, $type = <enabled | disabled | all>)

Retrieve snort rules registered in the NetPass database. Returns
an C<array reference> on success, C<undef> on failure.

=cut

sub getSnortRules {
	my $self   = shift;
	my $secret = shift;
	my $type   = shift;
	my $np	   = $::np;
	my @aref;

	return undef unless ($self->$check_soap_auth($secret));
	return undef unless ($type =~ /^(enabled|disabled|all)$/);

	my $network = $np->cfg->getNetworks();
	return undef unless (defined ($network));

	_log("DEBUG", "retrieving snort rules");

	foreach my $nw (@$network) {
		my $qvlan = $np->cfg->quarantineVlan($nw);
		next unless defined $qvlan;
		push @aref, sprintf("pass tcp any any -> any any (vlan:%d;)\n", $qvlan);

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

=head2 my $results = processIP($secret, $ip, $sid, ...)

Arguments includes an ip address of the machine to process along with 
an array of snort sids. This method will then determine and take
necessary actions against the specified ip address. Returns C<quarantined>
if the ip will be quarantined, C<nothing> if no action is taken, and 
C<undef> on failure.

=cut

sub processIP {
	my $self   = shift;
	my $secret = shift;
	my $ip	   = shift;
	my @sids   = @_;
	my $np	   = $::np;
	my @msgs;

	return undef unless ($self->$check_soap_auth($secret)); 

	my $network = $np->cfg->getMatchingNetwork($ip);
	if (!$network) {
		_log("ERROR", "Unable to determine network for $ip");
		return undef;
	}

	my $mode = $np->cfg->snortEnabled($network);
	if ($mode eq "disabled") {
		_log("DEBUG", "Snort is disabled on $network");
		return ("nothing");
	}

	my $mac = "";
	push @msgs, map(print("snort quarantined $ip $mac for violation of $_ snort rule."),
		        @sids); 

	$np->db->alert (
			 severity	=> 'NOTICE',
			 mac		=> $mac,
			 ip		=> $ip,
			 user		=> 'snort',
			 @msgs
		       );
	return ("nothing") if $mode eq "not_really"; 

	foreach my $sid (@sids) {
		my $rv = $np->db->addResult (
				      		mac	=> $mac,
				      		type	=> 'snort',
				      		id	=> $sid 
				    	    );

		if ($rv eq "invalid mac") {
			_log("ERROR", "Invalid mac $mac");
			return undef;
		}
		if ($rv eq "db failure") {
			_log("ERROR", "database failure");
			return undef;	
		}
		if ($rv ne "duplicate result" || $rv != 0) {
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
