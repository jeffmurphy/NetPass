#!/usr/bin/perl -w

=head1 NAME

 npsubagent.pl

=head1 SYNOPSIS

 npsubagent.pl <-o basoid> <-c brctl_cmd> <-m npvnat_macs> <-n npvnat_nummacs> <-t timeout> <-r refreshrate> <-b dev> traphost
     -o	baseoid		  snmp base oid
     -m npvnat_macs	  the npvnat macs file in the /proc fs
     -n npvnat_nummacs	  the npvnat nummacs file in the proc fs
     -t timeout		  the amount of time to wait before sending a linkdown
			  trap for a mac disappearing from out mac table
     -r refreshrate	  how often we will refresh our mac table  
     -b dev		  the name of the bridge device (default br0)  
     -h                   this message


=head1 DESCRIPTION

This script is an snmp interface to ebtables with the npvnat module.

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
use NetSNMP::agent (':all');
use NetSNMP::OID (':all');
use NetSNMP::ASN (':all');
use FileHandle;

my %opts;
getopts('o:c:m:n:t:r:h', \%opts);

my $TRAPHOST	= shift;
pod2usage(2) if (!defined $TRAPHOST); 
pod2usage(2) if exists $opts{'h'};

my $BASEOID	= (exists $opts{'o'}) ? $opts{'o'} : ".1.3.6.1.4.1.8072.9999.9999.7375";
my $REFRESHRATE = (exists $opts{'r'}) ? $opts{'r'} : 5;
my $TIMEOUT     = (exists $opts{'t'}) ? $opts{'t'} : 3600;

my $PROCEBTMAC  = "/proc/ebtables/npvnat/macs";
if (exists $opts{'m'} && $opts{'m'} && -e $opts{'m'}) {
	$PROCEBTMAC = $opts{'m'};		
}
my $PROCEBTNMAC = "/proc/ebtables/npvnat/nummacs";
if (exists $opts{'n'} && $opts{'n'} && -e $opts{'n'}) {
        $PROCEBTNMAC = $opts{'n'};
}
my $BRCTLCMD    = "/usr/local/sbin/brctl";
if (exists $opts{'c'} && $opts{'c'} && -e $opts{'c'}) {
        $BRCTLCMD = $opts{'c'};
}
my $BRDEV       = "br0";
if (exists $opts{'b'} && $opts{'b'} && -e $opts{'b'}) {
        $BRDEV = $opts{'b'};
}

die "ERROR, $PROCEBTMAC doesn't exist!" if (!-e $PROCEBTMAC);
die "ERROR, $PROCEBTNMAC doesn't exist!" if (!-e $PROCEBTNMAC);
die "ERROR, $BRCTLCMD doesn't exist!" if (!-e $BRCTLCMD);

$BRCTLCMD .= " showmacs $BRDEV";

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
			sendTrap($mactable->{$m}{port}, 'down', $TRAPHOST);
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
			sendTrap($mactable->{$m}{port}, 'up', $TRAPHOST);
		}

		$ltime += $REFRESHRATE;
	}
}

$agent->shutdown();
exit 0;

sub sendTrap {
	my($port, $traptype, $traphost) = @_;
	my $enterpriseoid;
	my $generic;
	my $portoidbase = $BASEOID.'1';

	use Net::SNMP qw(:ALL);

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

	my ($session, $error) = Net::SNMP->session(
							-hostname	=> $traphost,
							-port		=> SNMP_TRAP_PORT,
							-community	=> 'public'	
						  );

	if (!defined($session)) {
		warn "Unable to connect to $traphost";
		return -1;
	}

	my $res = $session->trap (
				  -enterprise	=> $enterpriseoid,
				  -agentaddr	=> $traphost,
				  -generictrap	=> $generic,
				  -specifictrap	=> 0,
				  -varbindlist	=> [$portoidbase.'.'.$port, INTEGER, 1]
		    		 );

	if (!defined $res) {
		warn "Unable to send trap ".$session->error();
		return -1;
	}

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

	$fh->open("$BRCTLCMD |") || return -1;
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
