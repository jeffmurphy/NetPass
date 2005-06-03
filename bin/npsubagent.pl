#!/usr/bin/perl -w

use strict;
use NetSNMP::agent (':all');
use NetSNMP::OID (':all');
use NetSNMP::ASN (':all');
use FileHandle;
use SNMP;

my $BASEOID	= ".1.3.6.1.4.1.8072.9999.9999.7375";
my $BRCTLCMD    = "/usr/local/sbin/brctl showmacs br0 |";
my $PROCEBTMAC  = "/proc/ebtables/npvnat/macs";
my $PROCEBTNMAC = "/proc/ebtables/npvnat/nummacs";
my $REFRESHRATE = 5;    # refresh rate
my $TIMEOUT     = 3600; # 1hr
my $TRAPHOST	= "npw2-d.cit.buffalo.edu";
my $TRAPHOSTCOM	= "50ohm";

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
	my $time = time();

	if (($ltime + $REFRESHRATE) < $time) {
		my $mactb = getMacTable();
		next unless ref($mactb) eq 'HASH';

		foreach my $m (keys %$mactable) {
			next if exists $mactb->{$m} ||
				($mactable->{$m}{lastseen} + $TIMEOUT > $time);

			# make the port available
			push @$freeports, $mactable->{$m}{port};

			# delete mac from main mactable
			delete $mactable->{$m};

			# send linkdown trap here...
		}

		foreach my $m (keys %$mactb) {
			if (exists $mactable->{$m}) {
				$mactable->{$m}{lastseen} = $time;
				next;
			}
			# assign a port
			$mactable->{$m}{port}     = shift @$freeports;
			$mactable->{$m}{decmac}   = $mactb->{$m};
			$mactable->{$m}{status}   = "quar";
			$mactable->{$m}{lastseen} = $time;

			# send linkup trap here...
			sendTrap($mactable->{$m}{port}, 'up', $TRAPHOST, $TRAPHOSTCOM);
		}

		$ltime += $REFRESHRATE;
	}
}

$agent->shutdown();
exit 0;

sub sendTrap {

	my($port, $traptype, $traphost, $traphostcom) = @_;
	my $enterpriseoid;
	my $generic;
	my $portoidbase = $BASEOID.'1';

print "sending linkup trap\n";

	#
	# enterprise oids
	# .1.3.6.1.4.1.45.3.30.2 linkdown trap
	# .1.3.6.1.4.1.45.3.35.1 linkup trap
	#

	if ($traptype eq "up") {
		$enterpriseoid  = ".1.3.6.1.4.1.45.3.35.1";
		$generic	= 3;
	} else {
		$enterpriseoid  = ".1.3.6.1.4.1.45.3.30.2";
		$generic	= 2;
	}

	my $snmp = new SNMP::Session(
					DestHost   => $traphost,
					RemotePort => 162,
				    );

	if (!defined($snmp)) {
		warn "Unable to connect to $traphost";
		return -1;
	}
print "about to send trap\n";
	$snmp->trap (
			enterprise	=> $enterpriseoid,
			agent		=> $traphost,
			generic		=> $generic,
			specific	=> 0,
			[[$portoidbase, $port, 1]]
		    );
print "trap sent\n";

	return 1;
}

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

	$fh->open($BRCTLCMD) || return -1;
	while (my $l = $fh->getline) {
		if ($l =~ /(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})\s+no/) {
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
	# basoid.2.mac_in_dec = status either quar/unquar
	#

	my ($handler, $registration_info, $request_info, $requests) = @_;
	my $request;
	my $macbaseoid		= $BASEOID.'.1';
	my $statusbaseoid	= $BASEOID.'.2';
	for($request = $requests; $request; $request = $request->next()) {
		my $oid = $request->getOID();

		if ($request_info->getMode() == MODE_GET) {
			if ($oid > new NetSNMP::OID($macbaseoid)) {
				foreach my $m (keys %$mactable) {
					if ($oid == new NetSNMP::OID($macbaseoid.'.'.$mactable->{$m}{decmac})) {
						$request->setValue(ASN_INTEGER, $mactable->{$m}{port});
					} elsif ($oid == new NetSNMP::OID($statusbaseoid.'.'.$mactable->{$m}{decmac})) {
						$request->setValue(ASN_OCTET_STR, $mactable->{$m}{status});
					}
				}
			}
		} elsif ($request_info->getMode() == MODE_GETNEXT) {
			if ($oid >= new NetSNMP::OID($BASEOID) &&
			    $oid < new NetSNMP::OID($statusbaseoid)) {

				foreach my $m (sort {new NetSNMP::OID($mactable->{$a}{decmac}) <=>
						     new NetSNMP::OID($mactable->{$b}{decmac})} keys %$mactable) {
					if ($oid < new NetSNMP::OID($macbaseoid.'.'.$mactable->{$m}{decmac})) {
						$request->setOID($macbaseoid.'.'.$mactable->{$m}{decmac});
						$request->setValue(ASN_INTEGER, $mactable->{$m}{port});
						goto done;
					}
				}
				$oid = new NetSNMP::OID($statusbaseoid);
			}
 
			if ($oid >= new NetSNMP::OID($statusbaseoid) && $oid < new NetSNMP::OID($BASEOID.'.3')) {
                        	foreach my $m (sort {new NetSNMP::OID($mactable->{$a}{decmac}) <=>
                                                     new NetSNMP::OID($mactable->{$b}{decmac})} keys %$mactable) {
                                	if ($oid < new NetSNMP::OID($statusbaseoid.'.'.$mactable->{$m}{decmac})) {
                                        	$request->setOID($statusbaseoid.'.'.$mactable->{$m}{decmac});
                                        	$request->setValue(ASN_OCTET_STR, $mactable->{$m}{status});
                                                goto done;
                                        }
                                }
			}
		} elsif ($request_info->getMode() == MODE_SET_RESERVE1) {
			foreach my $m (keys %$mactable) {
				if ($oid == new NetSNMP::OID ($statusbaseoid.'.'.$mactable->{$m}{decmac})) {
					goto done if ($request->getValue() =~ /^\"(quar|unquar)\"$/); 
					$request->setError($request_info, SNMP_ERR_WRONGVALUE);	
				}
			}
			$request->setError($request_info, SNMP_ERR_NOSUCHNAME);

		} elsif ($request_info->getMode() == MODE_SET_ACTION) {
			my $val =  $request->getValue();
			$val    =~ s/\"//g;

			my $o = new NetSNMP::OID($statusbaseoid);

			if ($oid =~ /^$o\.(\d+\.\d+\.\d+\.\d+\.\d+\.\d+)$/) {
				my $mac = sprintf("%x:%x:%x:%x:%x:%x", split(/\./, $1));

				if ($val eq "unquar") {
					addMac($mac);
				} else {
					delMac($mac);
				}

				$mactable->{$mac}{status} = $val;
				goto done;
			}
			$request->setError($request_info, SNMP_ERR_INCONSISTENTVALUE);

		}
done:
	}
}
