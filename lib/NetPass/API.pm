package NetPass::API;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw("/opt/netpass/lib);
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

sub check_soap_auth {
        my $self         = shift;
        my $their_secret = shift;
        my $rip          = $::remote_ip;
        my $np           = $::np;
	my $cfg		 = $np->cfg();

        my $secret       = $cfg->npapiSecret();
        my $my_secret    = md5_hex($rip.$secret);

        return ($their_secret eq $my_secret) ? 1 : 0;
}

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

	return undef unless ($self->check_soap_auth($secret));
	return undef unless ($type =~ /^(enabled|disabled|all)$/);

	my $network = $cfg->getNetworks();
	return undef unless (defined ($network));

	push @aref, map($cfg->quarantineVlan($_), @$network);

	my $rules = $dbh->getSnortRules($type);
	return undef unless defined($rules);

	push @aref, @$rules;
	return \@aref;
}

1;
