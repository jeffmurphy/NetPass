# $Header: /tmp/netpass/NetPass/lib/NetPass/Network.pm,v 1.6 2005/08/31 20:09:17 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


package NetPass::Network;

use Carp;
use Net::DNS;
use NetPass::LOG qw(_log);

require Exporter;

@ISA = qw (Exporter);
@EXPORT_OK = qw (searchArpCache host2addr ip2int cidr2int int2cidr int2ip
		 allOnesBroadcast);

use strict;

=head1 NAME

NetPass::Network

=head1 DESCRIPTION

A collection of networking related routines (not methods). 

=cut

my @cidr_to_int = (
		   0x00000000, #/0
		   0x80000000, #/1
		   0xc0000000, #/2
		   0xe0000000, #/3
		   0xf0000000, #/4
		   0xf8000000, #/5
		   0xfc000000, #/6
		   0xfe000000, #/7
		   0xff000000, #/8
		   0xff800000, #/9
		   0xffc00000, #/10
		   0xffe00000, #/11
		   0xfff00000, #/12
		   0xfff80000, #/13
		   0xfffc0000, #/14
		   0xfffe0000, #/15
		   0xffff0000, #/16
		   0xffff8000, #/17
		   0xffffc000, #/18
		   0xffffe000, #/19
		   0xfffff000, #/20
		   0xfffff800, #/21
		   0xfffffc00, #/22
		   0xfffffe00, #/23
		   0xffffff00, #/24
		   0xffffff80, #/25
		   0xffffffc0, #/26
		   0xffffffe0, #/27
		   0xfffffff0, #/28
		   0xfffffff8, #/29
		   0xfffffffc, #/30
		   0xfffffffe, #/31
		   0xffffffff  #/32
		  );

my %int_to_cidr;

for(my $m=0 ; $m <= $#cidr_to_int ; $m++) {
	$int_to_cidr { $cidr_to_int[$m] } = $m;
}

=head2 $dotted = int2ip($int)

Given an integer, return it in dotted quad notation.

=cut

sub int2ip {
        my $i = shift;

        $i &= 0xFFFFFFFF;
        return join('.', (($i>>24) & 0xFF),
                         (($i>>16) & 0xFF),
		         (($i>> 8) & 0xFF),
		         (($i    ) & 0xFF));
}


=head2 $bitlen = int2cidr($mask)

Given an integer bit mask, return the bit length.

=cut

sub int2cidr {
	my $mask = shift;
	return $int_to_cidr{$mask} if (exists $int_to_cidr{$mask});
	return undef;
}

=head2 ($ip, $mask) = cidr2int($network)

Given an IPV4, possibly in CIDR notation (128.205.1.20, 128.205.1.0/24) return
the IP and Mask as integers. If the trailing /# is not present, /32 will be 
automatically appended.

=cut

sub cidr2int {
	my $c = shift;
	
	$c .= "/32" unless ($c =~ /\/\d+/);
	
	if($c !~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d+)$/) {
		die Carp::longmess("cidr2int: \"$c\" doesnt look like a.b.c.d/f");
	}
	
	my $i   = ip2int($1);
	my $cbf = $2;
	my $m;
	
	# for the mask, did they give us, eg "/24" or did they 
	# give us "/255.255.255.0" ?
	
	if ($cbf =~ /^\d+$/) { # /24
		die Carp::longmess("cidr bit field must be between 1 and 32") 
		  if ( $cbf < 1 || $cbf > 32 );
		$m = $cidr_to_int[$cbf];
	} else { #/255.255.255.0
		$m = ip2int($cbf);
	}
	
	return($i, $m);
}

=head2 $integer = ip2int($ip)

   Given an IPv4 address, return it in integer format.

=cut

sub ip2int {
	my $i = shift;
	
	if ($i !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
		die Carp::longmess("ip2int: \"$i\" doesnt look like an ip address to me");
	}
	
	my @o = split(/\./, $i);
	return ( ($o[0] << 24) |
		 ($o[1] << 16) | 
		 ($o[2] <<  8) |
		 ($o[3]      ) );
}

=head2 $ip = host2addr($hostname || $ipaddress)

Given a hostname, translate it (using Net::DNS) to its corresponding
IP address. If you pass in an IP address, we recognize that and simply
return it.

=cut

sub host2addr {
	my $hn    = shift;
	my $res   = new Net::DNS::Resolver;
	my $query = $res->search($hn);
	
	return $hn if ($hn =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
	
	my $addr;
	
	if ($query) {
		foreach my $rr ($query->answer) {
			next unless $rr->type eq "A";
			return $rr->address;
			last;
		}
	} else {
		die Carp::longmess("cant resolve hostname ($hn) to an address: " .
				   $res->errorstring);
	}
	#notreached
}


=head2 $mac = searchArpCache($ip, $includeIncomplete = 1)

Search through the ARP cache on the localhost for the specified IP
address. If multiple matches are found, a hash ref is returned mapping
IPs to MACs. If only one match is found, a scalar is returned containing
the MAC address. If C<$includeIncomplete> is 1 (true) then we'll include
MACs that the "arp" command classifies as "incomplete". The default is
to include "incomplete" addresses.

The IP you pass in can be in a variety of formats:

=over 8

        Distinct address: 128.205.1.20

        Regular Expression: 128\.205\.1\..*

        Network Notation: 128.205.1.0/24

=back

C<undef> on failure.

B<Note: this is not an object oriented routine. Just call it directly.>

=cut

sub searchArpCache {
	my $ip   = shift;
	my $ii   = shift;
	$ii    ||= 1;
	
	_log("INFO", "searching arp cache for $ip\n");
	
	my $fh = new FileHandle "/sbin/arp -na |";
	if (!defined($fh)) {
		_log "ERROR", "failed to open /sbin/arp: $!\n";
		return undef;
	}
	my $mac = undef;
	my @lines = <$fh>;
	$fh->close;
	return undef unless $#lines > -1;
	
	
	if ($ip =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2})$/) {
		# cidr network notation passed in
		
		my ($nw, $mask) = cidr2int($1);
		
		my %rv;
		
		foreach my $line (@lines) {
			if ($line =~ /\(([\d\.]+)\)\s+at\s+(\S+)/) {
				my $ip2 = ip2int($1);
				$mac = $2;
				next if (!$ii && $mac =~ /incomplete/);
				my $mac2;
				foreach my $_mp (split(/:/, $mac)) {
					$mac2 .= substr("00".$_mp, -2);
				}
				$rv{$1} = $mac2 if (($ip2 & $mask) == $nw);
			}
		}
		return \%rv;
	}

	# distinct address or regexp passed in
		
	my @matches = grep {/\($ip\)\s+at\s+\S+/} @lines;
	return undef unless $#matches > -1;
		
	if ($#matches == 0) {
		$matches[0] =~ /\($ip\)\s+at\s+(\S+)/;
		my $mac = $1;
		my $mac2 = '';
		foreach my $_mp (split(/:/, $mac)) {
			$mac2 .= substr("00".$_mp, -2);
		}
		$mac =~ tr [A-Z] [a-z];
		$mac2 =~ tr [A-Z] [a-z];
		return undef if (!$ii && $mac =~ /incomplete/);
		return $mac2;
	}
	
	my $macs = {};
	
	foreach my $l (@matches) {
		#_log "INFO", "($ip) arp cache: $l";
		chomp $l;
		if($l =~ /\(($ip)\)\s+at\s+(\S+)/) {
		        my $ip  = $1;
			my $mac = $2;
			my $mac2 = '';
			foreach my $_mp (split(/:/, $mac)) {
				$mac2 .= substr("00".$_mp, -2);
			}
			$mac =~ tr [A-Z] [a-z];
			$mac2 =~ tr [A-Z] [a-z];
			next if (!$ii && $mac =~ /incomplete/);
			$macs->{$ip} = $mac2;
		} 
        }
        return $macs;
}

=head2 my $dotted = allOnesBroadcast($dottedCidr)

Given a network in CIDR notation, determine the all ones broadcast
address and return it.

=cut

sub allOnesBroadcast {
	my $nw_ = shift;
	my ($nw, $mask) = cidr2int($nw_);
	my $im = $mask ^ 0xFFFFFFFF;
	my $ones = $nw | $im;
	return int2ip($ones);
}

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: Network.pm,v 1.6 2005/08/31 20:09:17 jeffmurphy Exp $

=cut

1;
