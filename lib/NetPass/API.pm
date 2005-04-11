package NetPass::API;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw("/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use Digest::MD5 qw(md5_hex);

=head1 NAME

NetPass::Config - NetPass Configuration File Interface

=head1 SYNOPSIS

    use NetPass::API;

=head1 DESCRIPTION

This object provides access to the NetPass configuration file. The configuration
file tracks things such as:

=head1 METHODS

=cut

my $check_soap_auth = sub {
        my $self         = shift;
        my $their_secret = shift;
        my $rip          = $::remote_ip;
        my $np           = $::np;
	my $cfg		 = $np->cfg();

        my $secret       = $cfg->npapiSecret();
        my $my_secret    = md5_hex($rip.$secret);

        return ($their_secret eq $my_secret) ? 1 : 0;
};

=head2 $aref = NetPass::API::getSnortRules($secret, $type = <enabled | disabled | all>)

Retrieve snort rules registered in the NetPass database. Returns
an C<array reference> on success, C<undef> on failure.

=cut

sub getSnortRules {
	my $self   = shift;
	my $secret = shift;
	my $type   = shift;
	my $np	   = $::np;
	my $dbh	   = $::dbh;
	my $cfg	   = $np->cfg();
	my @aref;

	return undef unless ($self->$check_soap_auth($secret));
	return undef unless ($type =~ /^(enabled|disabled|all)$/);

	my $network = $cfg->getNetworks();
	return undef unless (defined ($network));

	_log("DEBUG", "retrieving snort rules");

	# hafta figure out a snort rule to block already quarantined
	# machines... 
	#push @aref, map($cfg->quarantineVlan($_), @$network);

	my $rules = $dbh->getSnortRules($type);
	_log("ERROR", "Unable to retrieve rules from database")
	  	     unless defined($rules);
	return undef unless defined($rules);

	push @aref, @$rules;
	return \@aref;
}

=head2 echo()

Used to determine if we have a valid connection, Returns 1 always.

=cut

sub echo {1}

1;
