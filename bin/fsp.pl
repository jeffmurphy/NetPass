#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/fsp.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 fsp.pl (Find Switch Port)

=head1 SYNOPSIS

 fsp.pl [-c config] [-D] <macaddr> <ipaddr>
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -D             enable debugging

=head1 OPTIONS

<ipaddr> is used to narrow the search. both <macaddr> and <ipaddr>
are required.

=head1 DESCRIPTION

This script will search for a given MAC/IP. It will do so using the
tree search and then the linear search method. It will report the time it took for 
each seach to complete. Good for troubleshooting, testing, etc.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: fsp.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;
require NetPass::Config;

pod2usage(1) if $#ARGV < 1;

my %opts;
getopts('c:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};


my ($ma, $ip) = (shift, shift);

my $np = new NetPass(-config => defined $opts{'c'} ? $opts{'c'} :
                                "/opt/netpass/etc/netpass.conf",
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to create NetPass object" unless defined $np;

my $nw = $np->cfg->getMatchingNetwork($ip);

print "our network is: ".$nw."\n";
print "our bsw     is: ".$np->cfg->getBSW($nw)."\n";

print "calling findOurSwitchPort...\n";

my $t1 = time();
my ($sw, $po, $mph, $pmh) = $np->findOurSwitchPort($ma, $ip);
print "tree took ".(time()-$t1)." seconds\n";

($sw, $po, $mph, $pmh) = $np->findOurSwitchPort_linear($ma, $ip);

print "linear took ".(time()-$t1)." seconds\n";

exit 0;
