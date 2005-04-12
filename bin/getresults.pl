#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/getresults.pl,v 1.2 2005/04/12 14:18:11 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 getresults.pl

=head1 SYNOPSIS

 getresults.pl [-c cstr] [-U dbuser/dbpass] [-D] [-t nessus|snort|manual]
               [-s pending|fixed|user-fixed|any] [-i id]
               <-m macaddr>

     -c configFile  [default /opt/netpass/etc/netpass.conf]
     -D             enable debugging
     -t [type]      
     -s [status]
     -i [id] 
     -m macaddress  no colons, etc. 

=head1 OPTIONS

The MAC address parameter is required. The default for type is "any type" 
if not specified. The default for status is 'pending'.

=head1 DESCRIPTION

Show the results that match the given criteria.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: getresults.pl,v 1.2 2005/04/12 14:18:11 jeffmurphy Exp $

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
getopts('c:t:m:s:i:U:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};

pod2usage(2)
if ((exists $opts{'t'} && ($opts{'t'} !~ /^nessus|snort|manual$/)) ||
    (exists $opts{'m'} && ($opts{'m'} !~ /^[0-9a-f]+$/i))           ||
    (exists $opts{'i'} && ($opts{'m'} eq ""))                      ||
    (exists $opts{'s'} && ($opts{'s'} !~ /^pending|fixed|user-fixed|any$/)));

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my %params;
$params{'-type'}   = $opts{'t'} if (exists $opts{'t'});
$params{'-status'} = $opts{'s'} if (exists $opts{'s'});
$params{'-id'}     = $opts{'i'} if (exists $opts{'i'});

my $r = $np->db->getResults(-mac => $opts{'m'}, %params);

if (ref($r) eq "HASH") {
	printf("Results for address: ". $opts{'m'}."\n");
	printf("%-20.20s %-10.10s %-10.10s %s\n", "Time", "Status", "Type", "ID");
	print "-"x78, "\n";
	if ($#{$r->{'timestamp'}} > -1) {
		for(my $i = 0; $i <= $#{$r->{'timestamp'}} ; $i++) {
			printf("%-20.20s %-10.10s %-10.10s %s\n", 
			       scalar(localtime($r->{'timestamp'}->[$i])),
			       $r->{'status'}->[$i],
			       $r->{'type'}->[$i],
			       $r->{'id'}->[$i]);
		}
	} else {
		print "No matching results.\n";
	}
} else {
	print "Error: $r\n";
}

exit 0;
