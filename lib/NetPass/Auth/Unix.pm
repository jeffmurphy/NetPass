# $Header: /tmp/netpass/NetPass/lib/NetPass/Auth/Unix.pm,v 1.1 2004/12/31 19:09:09 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package NetPass::Auth::Unix;

use strict;
no strict 'refs';

use Class::ParmList qw(simple_parms parse_parms);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use base 'NetPass';

use vars qw(@ISA);

@ISA = qw(NetPass);
my $VERSION = '1.0001';

=head1 NAME

NetPass::Auth::Unix - Routines for authenticating against local Unix files

=head1 SYNOPSIS

 use NetPass;
 $bool = $np->authenticateUser($username, $password)

 $err = $np->error

=head1 DESCRIPTION

This module is a subclass of NetPass. It's not intended to be called
directly, but should be referenced via the NetPass object.

=cut

sub authenticateUser {
    my $np = shift;
    my ($u, $p) = (shift, shift);

    my $sysPass = getpwnam($u);
    if ($sysPass) {
	    my $salt = substr($sysPass, 0, 2);
	    my $encGiven = crypt($p, $salt);
	    return 1 if ($encGiven eq $sysPass);
    }
    return 0;
}

=AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: Unix.pm,v 1.1 2004/12/31 19:09:09 jeffmurphy Exp $

=cut

1;

