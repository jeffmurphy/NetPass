package NetPass::API;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw("/opt/netpass/lib);
use NetPass::Config;
use Digest::MD5 qw(md5_hex);

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

sub foo {
	my $self   = shift;
	my $secret = shift;
	my $arg	   = shift;

	return "yoyoyo".$arg if ($self->check_soap_auth($secret));
}

sub getSnortRuleFile {
	my $self   = shift;
	my $secret = shift;
	my $np	   = $::np;

	return -1 if (!$self->check_soap_auth($secret));

	# get vlanids for quarantined networks

	# call DB::Config::getSnortRules	

}

1;
