# $Header: /tmp/netpass/NetPass/lib/NetPass/Stats/Attic/Network.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


package NetPass::Stats::Network;

=head1 NAME

NetPass::Stats::Network - used in conjuction with npstatd to provide remote access
to the NetPass::Stats object.

=head1 SYNOPSIS

    use NetPass::Stats::Network;
    use Digest::MD5 qw(md5_hex);

    my $secret = md5_hex("localaddr"."secret");
    my $ncfg = new NetPass::Stats::Network($secret);

=head1 DESCRIPTION

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: Network.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

=cut

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw("/opt/netpass/lib);
use NetPass::Stats;
use Digest::MD5 qw(md5_hex);

sub AUTOLOAD {
        no strict;
        return if($AUTOLOAD =~ /::DESTROY$/);
        if ($AUTOLOAD=~/new$/) {
		my $self   = shift;
		my $secret = shift;
                my $field = "NetPass::Stats::new";

		return 0 unless ($self->check_soap_auth($::cfg, $secret));  
                my $rv = &$field($self, $::cfg->{'cf'});
		$rv->{soap_auth} = $secret;

		return $rv;
	} elsif ($AUTOLOAD=~/(check_soap_auth)$/) {
                my $field = $1;
                &$field(@_);
	} elsif ($AUTOLOAD=~/(\w+)$/) {
		my $self = shift;
		my $field = "NetPass::Stats::".$1;

		return 0 unless ($self->check_soap_auth($::cfg, $self->{soap_auth}));

		&$field($self, @_);
        } else {
                Carp::confess("Cannot figure out field name from '$AUTOLOAD'");
        }
}

sub check_soap_auth {
	my $self         = shift;
	my $cfg          = shift;
	my $their_secret = shift;
	my $rip          = $::remote_ip;

	my $secret       = $cfg->npcfgdSecret(); 
	my $my_secret    = md5_hex($rip.$secret);

	return ($their_secret eq $my_secret) ? 1 : 0;
}

1;
