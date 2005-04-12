#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/moveport.pl,v 1.3 2005/04/12 15:24:08 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

moveport.pl - move a switchport between the "unquarantine" (fully functional)
and quarantine VLANs.

=head1 SYNOPSIS

 moveport.pl [-c cstr] [-U dbuser/dbpass] [-n] [-q] [-D] <switch> <port> <unquarantine | quarantine>
     -c cstr        db connect string
     -U user/pass   db user[/pass]
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging

=head1 OPTIONS

=over 8

=item B<-c cstr>

Specify an alternate database to connect to.

=item B<-U user/pass>

Connect to database using these credentials.

=item B<-q>

Be quiet, don't print anything. Just exit with non-zero status if 
an error occurred. Otherwise, exit with zero status.

=item B<-n>

"Not really". Tell us what you will do, but don't really do it (this flag
negates the C<-q> flag)

=item B<-D> 

Enable debugging output. 

=item B<switch>

Hostname or IP address of the switch we want to operate on.

=item B<port>

Port number to operate on.

=item B<unquarantine | quarantine>

For lack of a better term, move the port into the "unquarantine" or "quarantine" VLAN. Any existing
VLAN membership will be over-written. In other words, if, for some reason, the port is 
in multiple VLANs, it will be dropped from all of them and added to the "unquarantine" or "quarantine"
VLAN (determined by examining the configuration file).

=back

=head1 DESCRIPTION

This script helps us move a switchport between the "unquarantine" and "quarantine" VLANs. The 
"unquarantine" VLAN is the "normal", fully routable, etc, VLAN. The user gets access to all of the
"normal" services. The "quarantine" VLAN is a quarantine where the user is forced, via trunking,
to a NetPass server. 

Rather than specify the VLAN ID directly, this script will use the contents of the
configuration file to determine what the appropriate VLAN IDs are for the unquarantine and 
quarantine VLANs. 

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: moveport.pl,v 1.3 2005/04/12 15:24:08 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;

NetPass::LOG::init [ 'moveport', 'local0' ]; #*STDOUT;

pod2usage(1) if $#ARGV < 2;

my %opts;
getopts('c:qnDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my ($hn, $port, $vlan) = (shift, shift, shift);

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr  => exists $opts{'c'} ? $opts{'c'} : undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my $rv = $np->movePort(-switch => $hn, -port => $port, -vlan => $vlan);

if ( !exists $opts{'q'} && !$rv ) {
    print "ERROR $rv: ".$np->error()."\n";
    exit 255;
}


exit 0;
