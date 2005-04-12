#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/nessus.pl,v 1.3 2005/04/12 15:24:08 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

nessus.pl - purges mysql binlogs

=head1 SYNOPSIS

 nessus.pl [-c cstr] [-U user/pass] [-qDh?] [IP ADDRESS]

=head1 DESCRIPTION

This script will load the plugins from the database and will launch an
attack against the given machine. This is a testing script. It isn't used
by the system.

=AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: nessus.pl,v 1.3 2005/04/12 15:24:08 jeffmurphy Exp $

=cut

use strict;
use lib '/opt/netpass/lib';
use NetPass::Nessus;
use Data::Dumper;
use NetPass::LOG;

use DBI;

NetPass::LOG::init *STDOUT;


my $dbh = DBI->connect('dbi:mysql:netpass',
		       'root', '');

die DBI->errstr unless defined($dbh);

my $callback = sub {
	my $msg = shift;
	my $parms = shift;
	print "progress ", $msg->[2], " foo=", $parms->{'foo'}, "\n";
};


my $nessus = new NetPass::Nessus(
					host            => "127.0.0.1",
					port            => 1241,
					ssl             => 1,
					timeout => 1,
					debug   => 1,
					user    => 'netpass', password => 'netpass',
					callback => $callback,
					callbackparms => { foo => 123 }
				       );
$nessus->preferences( { host_expansion => 'none', safe_checks => 'yes', checks_read_timeout => 5 });

#$nessus->ntp_version('1.0');

my $sql = qq{SELECT pluginID FROM nessusScans where status = 'enabled'};

my $pids = $dbh->selectcol_arrayref($sql);
if($#$pids > -1) {
    print "loaded ",($#$pids + 1), " scans from database\n";
#    print Dumper(\@pids);
    
} else {
    print "no scans found in database.. ".DBI->errstr."\n";
    $dbh->disconnect;
    exit 255;
}

$dbh->disconnect;

my $addr = shift;
print "scanning $addr\n";

if( $nessus->login() ) {

	$nessus->plugin_set(join(';', @$pids));
		
	$nessus->attack($addr);
	printf(" info's = %d\n",$nessus->total_info);
	printf(" hole's = %d\n",$nessus->total_holes);
	print  " Duration: ".$nessus->duration." seconds\n";
}
else
  {
	  die("Nessus login failed %d: %s\n",$nessus->code,$nessus->error);
  }

exit 0;

