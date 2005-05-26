#!/usr/bin/perl -w

use strict;
use NetSNMP::agent (':all');
use NetSNMP::OID (':all');
use NetSNMP::ASN (':all');
use FileHandle;

my $BASEOID	= ".1.3.6.1.4.1.8072.9999.9999.7375";
my $PROCARPFILE = "/proc/net/arp";
my $PROCEBTMAC  = "/proc/ebtables/npvnat/macs";
my $PROCEBTNMAC = "/proc/ebtables/npvnat/nummacs";
my $REFRESHRATE = 5; # refresh rate

my $fh   	= new FileHandle();
my $mactable	= {};
my $freeports	= ();

# we are just starting clear all macs from ebtables
delAllMacs();

$fh->open($PROCEBTNMAC) || die "Unable to open $PROCEBTNMAC";
my $maxports = $fh->getline;
$fh->close();

push @$freeports, 1..$maxports;

my $agent = new NetSNMP::agent(
                               'Name'	=> "npsubagent",
                               'AgentX' => 1,
                              ) || die "Unable to create SNMP subagent";

$agent->register("npsubagent", $BASEOID, \&snmphandler) ||
	die "Unable to register SNMP subagent";



my $ltime = time();
while (1) {
	$agent->agent_check_and_process(0);


	if (($ltime + $REFRESHRATE) < time()) {
		my $mactb = getMacTable();
		next unless ref($mactb) eq 'HASH';

		foreach my $m (keys %$mactable) {
			next if exists $mactb->{$m};

			# make the port available
			push @$freeports, $mactable->{$m}{port};

			# delete mac from main mactable
			delete $mactable->{$m};

			# send linkdown trap here...
			# might hafta introduce a timer here
		}

		foreach my $m (keys %$mactb) {
			next if exists $mactable->{$m};

			# assign a port
			$mactable->{$m}{port}   = shift @$freeports;
			$mactable->{$m}{decmac} = $mactb->{$m};

			# send linkup trap here...
		}

		$ltime = $ltime + $REFRESHRATE;
	}
}

$agent->shutdown();
exit 0;

sub delMac {
	my $mac = shift;

	return -1 if ($mac !~ /\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}/);
	my $cmd = sprintf("echo \"del %s\" > %s", $mac, $PROCEBTMAC);

	return system($cmd);
}

sub addMac {
	my $mac = shift;

	return -1 if ($mac !~ /\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}/);
	my $cmd = sprintf("echo \"add %s\" > %s", $mac, $PROCEBTMAC);

	return system($cmd);
}

sub delAllMacs {
	my $fh = new FileHandle;
	my @macs;

	$fh->open($PROCEBTMAC) || return -1;
	@macs = $fh->getlines();
	$fh->close;

	foreach my $mac (@macs) {
		delMac($mac);
	}

	return 1;
}

sub getMacTable {
	my $fh = new FileHandle;
	my %mtable;

	$fh->open($PROCARPFILE) || return -1;
	while (my $l = $fh->getline) {
		if ($l =~ /(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})/) {
			my $m =  lc($1);
			$m    =~ s/0(\d{1,2})/$1/g;
			my @o = split(':', $m);
			$mtable{$m} = join('.', map(hex($_), @o));
		}
	}
	$fh->close();

	return \%mtable;
}

sub snmphandler {
	#
	# oid mapping
	# basoid.1.mac_in_dec = port
	#
	#

	my ($handler, $registration_info, $request_info, $requests) = @_;

	my $request;
	my $macbaseoid	= $BASEOID.'.1';
	for($request = $requests; $request; $request = $request->next()) {
		my $oid = $request->getOID();
print "requested oid = $oid\n";

		if ($request_info->getMode() == MODE_GET) {
			if ($oid > new NetSNMP::OID($macbaseoid)) {
				foreach my $m (keys %$mactable) {
					if ($oid == new NetSNMP::OID($macbaseoid.'.'.$mactable->{$m}{decmac})) {
						$request->setValue(ASN_INTEGER, $mactable->{$m}{port});
					}
				}
			}
		} elsif ($request_info->getMode() == MODE_GETNEXT) {
			if ($oid >= new NetSNMP::OID($BASEOID)) {
				foreach my $m (sort {new NetSNMP::OID($mactable->{$b}{decmac}) <=>
						     new NetSNMP::OID($mactable->{$a}{decmac})} keys %$mactable) {
                                        if ($oid < new NetSNMP::OID($macbaseoid.'.'.$mactable->{$m}{decmac})) {
						$request->setOID($macbaseoid.'.'.$mactable->{$m}{decmac});
						$request->setValue(ASN_INTEGER, $mactable->{$m}{port});
                                        }
				}
			}
		}
	}
}
