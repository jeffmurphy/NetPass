#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/moveport.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

moveport.pl - move a switchport between the "unquarantine" (fully functional)
and quarantine VLANs.

=head1 SYNOPSIS

 moveport.pl [-c config] [-n] [-q] [-D] <switch> <port> <unquarantine | quarantine>
     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging

=head1 OPTIONS

=over 8

=item B<-c configFile>

Specify an alternate NetPass configuration file. The default is
C</opt/netpass/etc/netpass.conf>

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

$Id: moveport.pl,v 1.2 2005/03/16 14:28:42 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;
require NetPass::Config;
#require NetPass::SNMP;

NetPass::LOG::init [ 'moveport', 'local0' ]; #*STDOUT;

pod2usage(1) if $#ARGV < 2;

my %opts;
getopts('c:qnDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

my ($hn, $port, $vlan) = (shift, shift, shift);

my $np = new NetPass(-config => defined $opts{'c'} ? $opts{'c'} :
                                "/opt/netpass/etc/netpass.conf",
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to create NetPass object" unless defined $np;

my $rv = $np->movePort(-switch => $hn, -port => $port, -vlan => $vlan);

if ( !exists $opts{'q'} && !$rv ) {
    print "ERROR $rv: ".$np->error()."\n";
    exit 255;
}


exit 0;
