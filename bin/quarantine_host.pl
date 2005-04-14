#!/usr/bin/perl -w

=head1 NAME

 quarantine_host.pl

=head1 SYNOPSIS

 quarantine_host.pl <-i snortid> <-S secret> <-s npapi server> [-p port] ipaddress
     -i snortid	   	  snort id to quarantines ipaddress over
     -S secret		  secret required to connect to npapi server       	 
     -s server		  npapi server
     -p port		  port of npapi server (default 20003)
     -h                   this message


=head1 DESCRIPTION

Force quarantine/unquarantine by using the NetPass::API object through SOAP. 

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
getopts('i:S:s:p:h', \%opts);
pod2usage(2) if exists $opts{'h'} || !exists $opts{'S'} ||
	       !exists $opts{'i'} || !exists $opts{'s'};

pod2usage(2) if ($opts{'s'} !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
pod2usage(2) unless ($opts{'i'} =~ /\d+/);

my $ip = shift;
pod2usage(2) if ($ip !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);

my $soap = createSoapConnection($opts{'s'});
die "Unable to connect to npapi server at $ip" unless defined $soap;

my $secret = md5_hex(hostip.$opts{'S'});
my $res    = eval {$soap->processIP($secret, $ip, $opts{'i'})->result};
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
