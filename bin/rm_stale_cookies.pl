#!/usr/bin/perl -w

# $Header: /tmp/netpass/NetPass/bin/rm_stale_cookies.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

rm_stale_cookies.pl - go thru the cookie store and delete old/duplicate cookies.

=head1 SYNOPSIS

 rm_stale_cookies.pl [-n] [-q] [-D] [-c config]
     -n             "not really"
     -q             be quiet. exit status only.
     -D             enable debugging
     -c             netpass.conf location

=head1 OPTIONS

=over 8

=item B<-q>

Be quiet, don't print anything. Just exit with non-zero status if 
an error occurred. Otherwise, exit with zero status.

=item B<-n>

"Not really". Tell us what you will do, but don't really do it (this flag
negates the C<-q> flag)

=item B<-c>

location of C<netpass.conf> - defaults to /opt/netpass/etc/netpass.conf

=item B<-D> 

Enable debugging output. Runs script in the foreground. Otherwise script will
run in the background.

=back

=head1 DESCRIPTION

Clients that constantly poll the webserver (weatherbug, etc) tend to make 
cookies accumulate in the cookie store. This script goes thru the store
periodically and cleans it out.

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: rm_stale_cookies.pl,v 1.1 2004/09/24 01:05:19 jeffmurphy Exp $

=cut

use strict;
use Apache::Session;
use Apache::Session::File;

my $base = "/cookies/data";

opendir(DH, $base) || die "opendir failed: $!";
my @cf = grep { /^[0-9a-z]/ && -f $base."/$_" } readdir(DH);
closedir DH;

foreach my $id (sort @cf) {
	print "file: $base/$id\n";
	my $mtime = (stat($base."/$id"))[9];
	my %session;
	tie %session, 'Apache::Session::File', $id ,
	  { Directory => '/cookies/data',
	    LockDirectory => '/cookies/lock'
	  };
	print scalar localtime($mtime), " ", 
	  $session{'remote_addr'}, " ", $session{'remote_mac'}, "\n";
	untie %session;
}

exit 0;
