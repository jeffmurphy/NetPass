# $Header: /tmp/netpass/NetPass/lib/NetPass/Auth/LDAP.pm,v 1.1 2004/12/31 19:09:09 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package NetPass::Auth::LDAP;

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

NetPass::Auth::LDAP - Routines for authenticating against LDAP

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

    for my $rs ($np->cfg()->{'cfg'}->keys('ldap')) {
	_log "DEBUG", "trying ldap server $rs\n";
	
	my $base = $np->{'cfg'}->{'cfg'}->obj('ldap')->obj($rs)->value('base');
	my $filt = $np->{'cfg'}->{'cfg'}->obj('ldap')->obj($rs)->value('filter');
	my $pswf = $np->{'cfg'}->{'cfg'}->obj('ldap')->obj($rs)->value('passwordField');

	my $filt2 = sprintf $filt, $u;

	_log("DEBUG", "trying ldap base=$base filter=$filt2\n");
	
	my $r = new Net::LDAP($rs);
	my $m = $ldap->bind;
	$m = $ldap->search(base => $base, filter => $filter);
	if ($m->code) {
		_log("ERROR", "ldap lookup failed base=$base filter=$filter error=".$m->error."\n");
		return 0;
	}

	my $pent = {$m->entries}[0]->get_value($pswf);
	$ldap->unbind;

	use MIME::Base64;
	my $decoded = decode_base64($pent);
	if ($pent =~ /^\{crypt\}(\S+)/) {
		my $pcr  = $1;
		my $salt = substr($pcr, 0, 2);
		my $encryptGiven = crypt($p, $salt);
		return 1 if ($pcr eq $encryptGiven);
	} else {
		_log("ERROR", "not sure how to handle non-{crypt} style LDAP passwords ($pent)\n");
	}
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

$Id: LDAP.pm,v 1.1 2004/12/31 19:09:09 jeffmurphy Exp $

=cut

1;

