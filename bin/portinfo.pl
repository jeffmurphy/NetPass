#!/opt/perl/bin/perl -w
#
# $Header: /tmp/netpass/NetPass/bin/portinfo.pl,v 1.6 2006/02/07 19:58:13 jeffmurphy Exp $
#
#   (c) 2006 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 NAME

 portinfo.pl <switch> <port>

=head1 SYNOPSIS

 portinfo.pl [-D] [-c cstr] [-U dbuser/dbpass] <switch> <port>
     -D             debugging to stdout
     -c cstr        db connect string
     -U user/pass   db user[/pass]

=head1 OPTIONS

 See above.

=head1 DESCRIPTION

Print out information about the given port.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2006 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: portinfo.pl,v 1.6 2006/02/07 19:58:13 jeffmurphy Exp $

=cut

use strict;
use Getopt::Std;
#use lib '/u1/project/netpass/NetPass-2/lib';
use lib '/opt/netpass/lib';
use FileHandle;
use Pod::Usage;

use NetPass::LOG qw(_log _cont);
require NetPass;


my $pagewidth = 70;

my %opts;
getopts('c:U:l:qDh?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};

NetPass::LOG::init *STDOUT if exists $opts{'D'};

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr  => exists $opts{'c'} ? $opts{'c'} : undef,
                     -dbuser => $dbuser, -dbpass => $dbpass,
                     -debug => exists $opts{'D'} ? 1 : 0,
                     -quiet => exists $opts{'q'} ? 1 : 0);

die "failed to connect to NetPass: $np" unless (ref($np) eq "NetPass");

my ($s,$p) = (shift, shift);
pod2usage(2) unless ($s && $p);

print box("Switch: $s Port: $p"), hr(" Current/Live Config ");

my ($vlan_uq, $vlan_qr) = $np->cfg->availableVlans(-switch => $s, -port => $p);

print "Managed: ", !defined $vlan_uq ? "No" : "Yes", "\n";

my $cn = ($np->cfg->getCommunities($s))[1];

if (!defined($cn)) {
	print "Switch community name isn't configured in NetPass. Can't query switch.\n";
} else {
	my ($uv, $qv) = $np->cfg->availableVlans(-switch => $s, -port => $p);
	my $snmp = new SNMP::Device('hostname'       => $s,
				    'snmp_community' => $cn);
	my $vlans = $snmp->get_vlan_membership($p);
	my $vlns;
	foreach my $vl (sort {$a <=> $b} @$vlans) {
		$vlns .= $vl;
		$vlns .= "(U)" if $vl == $uv;
		$vlns .= "(Q)" if $vl == $qv;
		$vlns .= " ";
	}
	my $defid = $snmp->get_default_vlan_id($p);
	my $h = $snmp->get_if_info($p);
	my ($mp, $pm) = $snmp->get_mac_port_table();
	
	print "Desc   : ", $h->{$p}->{if_descr}, "\n";
	
	print "VLANS  : $vlns\n";
	print "PVID   : $defid"; 
	print "(U)\n" if $defid == $uv;
	print "(Q)\n" if $defid == $qv;

	print "State  : ", ("?", "Up", "Down")[$h->{$p}->{if_status}], "\n";
	print "Trunk  ? ", ("?", "No", "Yes")[$h->{$p}->{vlan_port_type}], "\n";
	print "Speed  : ", ("?", "10", "100", "1000")[$h->{$p}->{speed}], " Mbps\n";
	print "Duplex : ", ("?", "Half", "Full")[$h->{$p}->{duplex}], "\n";
	print "Autoneg? ", ("?", "Enabled", "Disable")[$h->{$p}->{autoneg}], "\n";
	print "FCSErrs: ", $h->{$p}->{fcs_errors}, "\n";
	
	print "Macs   : ", exists $pm->{$p} ? join(',', @{$pm->{$p}}) : "none" , "\n";
}


# See if there's anything in the database for this port

my $d = $np->db->getRegisterInfo(-switch => $s, -port => $p);
if (ref($d) eq "HASH") {
	#use Data::Dumper; print Dumper($d);
	print hr(" Port Registrations ");
	printf("%12.12s %15.15s %10.10s %s\n", "MAC", "IP Address", "Username", "Status");
	foreach my $ma (sort keys %$d) {
		printf("%12.12s %15.15s %10.10s %s\n", $ma, 
		       $d->{$ma}->{'ipAddress'},
		       $d->{$ma}->{'username'},
		       $d->{$ma}->{'status'})
	}
} else {
	print "GRIErr : $d\n";
}


exit 0;

sub hr {
	my $t = shift;
	my $r = 3;
	my $l = $pagewidth - length($t) - $r;
	if ($l < 1) {
		$r = 0;
		$l = 0;
	}
	return '-'x$r . $t . '-'x$l . "\n";
}

sub center {
	my $t = shift;
	my $npw = shift;
	$npw ||= $pagewidth;
	return $t if (length($t) > $npw);
	my $s = ($npw - length($t)) / 2;
	return " "x$s . $t . " "x$s;
}

sub box {
	my $t = shift;
	my $l = $pagewidth - length($t) - 2;
	return $t, "\n" if ($l < 1);
	return hr(''). "|" . center($t, $pagewidth-2) . "|\n" . hr('');
}

