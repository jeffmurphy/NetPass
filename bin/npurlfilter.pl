#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/npurlfilter.pl,v 1.1 2005/04/27 03:54:06 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

npurlfilter.pl - Squid plugin for filtering/redirecting URLs

=head1 SYNOPSIS

 npurlfilter.pl [-D] [-c cstr] [-U dbuser/dbpass] [-t secs]
     -D             enable debugging
     -c             db connect string
     -U             db user[/pass]
     -t secs        how often to re-read url list from DB
                    (default 3600 seconds)

=head1 OPTIONS

=over 8

=item B<-D> 

Enable debugging output. Debugging output is sent to the _log() since
Squid reads from STDOUT, we can't send it there.

=item B<-c cstr> 

Connect to alternate database.

=item B<-U user/pass> 

Credentials to connect to the database with.

=item B<-t secs> 

How often do we refresh the URL list from the DB. Default: 3600 seconds.

=back

=head1 DESCRIPTION

This program is run via Squid's "redirect_program" directive. It reads URLs
from STDIN and sends URLs (via STDOUT) back to Squid. For most URLs, we
send back a redirect to the NetPass server's URL. Some URLs (configurable
via the NetPass adminstrative interface) are permitted through without redirection.

The URL list is re-read from the database once per hour unless "-t" is specified.
You can also connect to Squid and request the URL

http://netpass-reload-urlfilter./

to cause an immediate reload. This request must from localhost (127.0.0.1) or
it is ignored.

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

$Id: npurlfilter.pl,v 1.1 2005/04/27 03:54:06 jeffmurphy Exp $

=cut


use strict;
use Getopt::Std;
use lib '/opt/netpass/lib/';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;

my %opts : shared;
getopts('c:U:t:Dh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

$| = 1;

my $D   = exists $opts{'D'} ? 1 : 0;
my $rlt = exists $opts{'t'} ? $opts{'t'} : 3600; # reload time

NetPass::LOG::init [ 'npurlfilter', 'local0' ];

my $dbuser;
my $dbpass;
($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $cstr = exists $opts{'c'} ? $opts{'c'} : undef;

my $np = new NetPass(-cstr   => $cstr,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug => exists $opts{'D'} ? 1 : 0,
		     -quiet => exists $opts{'q'} ? 1 : 0);

if (ref($np) ne "NetPass") {
	_log("ERROR", "Failed to connect to NetPass: $np\n");
	safeMode();
}

my $llt = time();  # last load time
my $fl  = $np->db->getUrlFilters();

while(my $line = <STDIN>) {
	if ($llt+$rlt > time()) {
		$fl = $np->db->getUrlFilters();
	}

	chomp $line;

	my  @p      = split(/\s/, $line);
	my  $newurl = $p[0];

	study $p[0];

	if ($#p == 3) {
		if ( ($p[0] =~ /^http...netpass-reload-urlfilter/) && 
		     ($p[1] =~ /127\.0\.0\.1/) ) {
			$fl = $np->db->getUrlFilters();
			next;
		}

		if ($p[0] =~ /$fl->{'permit'}->{'re'}/) {
		}
		elsif ($p[0] =~ /$fl->{'soft-redirect'}->{'re'}/) {
			foreach my $pat (@{$fl->{'soft-redirect'}->{'list'}}) {
				$newurl = $fl->{'soft-redirect'}->{'hash'}->{$pat};
				last;
			}
		}
		elsif ($p[0] =~ /$fl->{'hard-redirect'}->{'re'}/) {
			foreach my $pat (@{$fl->{'soft-redirect'}->{'list'}}) {
				$newurl = '302:'.$fl->{'soft-redirect'}->{'hash'}->{$pat};
				last;
			}
		}
		elsif ($p[0] =~ /$fl->{'block'}->{'re'}/) {
			$newurl = '403:'.$p[0];
		}
	}
	print $newurl;
}


exit 0;


sub safeMode {
	_log("ERROR", "entering safe-mode\n");
	while(<STDIN>) {
		print;
	}
}
