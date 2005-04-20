#!/usr/bin/perl -w

=head1 NAME

 quarantine_host.pl

=head1 SYNOPSIS

 quarantine_host.pl <-S secret> <-s npapi server> <-i id,...> <-t type,...> [-p port] ipaddress
     -i id	   	  snort id to quarantines ipaddress over
     -S secret		  secret required to connect to npapi server       	 
     -s server		  npapi server
     -p port		  port of npapi server (default 20003)
     -t type		  what exactly quarantined this ip 
     -h                   this message


=head1 DESCRIPTION

Force quarantine by using the NetPass::API object through SOAP. 

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

=cut

use strict;
use Getopt::Std;
use Pod::Usage;
use Sys::HostIP;
use Digest::MD5 qw(md5_hex);
use SOAP::Transport::TCP;
use SOAP::Lite;

my $DEFAULTPORT	= 20003;

my %opts;
getopts('i:S:s:t:p:h', \%opts);
pod2usage(2) if exists $opts{'h'} || !exists $opts{'S'} ||
	       !exists $opts{'i'} || !exists $opts{'s'} ||
	       !exists $opts{'t'};

pod2usage(2) if ($opts{'s'} !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
pod2usage(2) unless ($opts{'i'} =~ /\d+/);

my $ip = shift;
pod2usage(2) if (!defined $ip || $ip !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);

my $id		= ();
my $type	= ();

if ($opts{'t'} =~ /\,/ || $opts{'i'} =~ /\,/) {
	@$id 	= split(',', $opts{'i'});
	@$type	= split(',', $opts{'t'});
	die "Number of types doesnt correspond with the number of ids"
		if ($#$id != $#$type);
} else {
	$id 	= $opts{'i'};
	$type	= $opts{'t'};
}

my $soap = createSoapConnection($opts{'s'});
die "Unable to connect to npapi server at $ip" unless defined $soap;

my $secret = md5_hex(hostip.$opts{'S'});
my $res    = eval {$soap->quarantineByIP( 
				    -secret	=> $secret,
				    -ip		=> $ip,
				    -type	=> $type,
				    -id		=> $id)->result};
die "Unable to quarantine $ip" unless defined $res;

exit 0;

sub createSoapConnection {
	my $npapiserver = shift;
	my $port  = (exists $opts{'p'} && $opts{'p'} =~ /\d+/)
		    ? $opts{'p'} : $DEFAULTPORT;
	my $proxy = "tcp://$npapiserver:$port";
	my $soap  = SOAP::Lite->new(
				     uri   => 'tcp://netpass/NetPass/API',
				     proxy => $proxy,
				   );

	return undef unless defined $soap;
	my $rv = eval {$soap->echo()->result};

	return $soap if $rv;
	return undef;
}
