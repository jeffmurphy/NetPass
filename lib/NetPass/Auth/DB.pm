# $Header: /tmp/netpass/NetPass/lib/NetPass/Auth/DB.pm,v 1.2 2005/04/06 20:50:37 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package NetPass::Auth::DB;

use strict;
no strict 'refs';

use Class::ParmList qw(simple_parms parse_parms);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use NetPass::DB;
use base 'NetPass';

use vars qw(@ISA);

@ISA = qw(NetPass);
my $VERSION = '1.0001';

=head1 NAME

NetPass::Auth::DB - Routines for authenticating against the local DB

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

    _log("DEBUG", "in DB::authUser\n");

    my $dbh = new NetPass::DB($np->cfg->dbSource,
			      $np->cfg->dbUsername,
			      $np->cfg->dbPassword,
			      1);

    if (!defined($dbh)) {
	    my $e = "failed to create NP:DB ".DBI->errstr."\n";
	    _log("ERROR", $e);
	    return 0;
    }

    my $encryptedPassFromDB = $dbh->getPasswd($u);
    my $salt = substr($encryptedPassFromDB, 0, 2);
    my $encryptedGivenPass = crypt($p, $salt);

    return 1 if ($encryptedGivenPass eq $encryptedPassFromDB);
    return 0;
}

=AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: DB.pm,v 1.2 2005/04/06 20:50:37 jeffmurphy Exp $

=cut

1;

