#!/usr/bin/perl

=head1 NAME

popvlanmap.pl - Generates a vlanmap entry for netpass.conf

=head1 SYNOPSIS

 popvlanmap.pl [-c config file]
     -c config file       location of netpass.conf

=cut

use strict;
use Getopt::Std;
use Pod::Usage;
use Data::Dumper;
use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass;
use NetPass::Config;
require NetPass::SNMP;

NetPass::LOG::init [ 'popvlanmap', 'local0' ]; #*STDOUT;

my %opts;

getopts('hc:', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'};
pod2usage(2) if !exists $opts{'c'};

my $np = new NetPass(-config => $opts{'c'} ? $opts{'c'} :
                      	        "/opt/netpass/etc/netpass.conf",
		    );

my $cfg  = $np->cfg();
my $map  = getvlanMap($cfg);
my $data = getSwitchInfo($cfg, $map);

my $networks = $cfg->getNetworks();

foreach my $net (@$networks) {
	my $switches = $cfg->getSwitches($net);

	foreach my $s (@$switches) {
		print $s.' '.formatPorts($data->{$s}, $map)."\n";
	}
}

sub getvlanMap() {
	my $cfg = shift;
	my $map = {};

	my $networks = $cfg->getNetworks();
	foreach my $net (@$networks) {
		$map->{$cfg->nonquarantineVlan($net)} = $cfg->quarantineVlan($net); 
	}

	return $map;
}

sub formatPorts() {
	my $d   = shift;
	my $map = shift;
	my $s = "";

	foreach my $vid (keys %$d) {
		my @t = sort {$a<=>$b} @{$d->{$vid}};

		my $start = $t[0];
		my $prev  = $start;
		my $cur   = $start;

		my @myline;

		for (my $i = 1 ; $i <= $#t ; $i++) {
   			$cur = $t[$i];
   			if ($cur - $prev > 1) {
       				# we've hit a break
       				if ($start != $prev) {
           				push @myline, "$start-$prev";
       				} else {
           				push @myline, "$start";
       				}
       				$prev = $start = $cur ;
   			} else {
       				$prev = $cur;
   			}
		}

		if ($start != $prev) {
    			push @myline, "$start-$prev";
		} else {
    			push @myline, "$start";
		}

		$s .= join(',', @myline).':'.$vid.'/'.$map->{$vid}.';';	
	}
	return $s;
}

sub getSwitchInfo() {
	my $cfg      = shift;
	my $map      = shift;
	my $networks = $cfg->getNetworks();
	my $data     = {};
	
	foreach my $net (@$networks) {
		my $switches = $cfg->getSwitches($net);		
		foreach my $s (@$switches) { 
			my($r, $w)   = $cfg->getCommunities($s);
			my $dev = new NetPass::SNMP(-hostname   => $s,
						    -community  => $r);

			my $ports = $dev->get_all_ports();
			foreach my $p (@$ports) {
				next if $dev->check_if_tagged($p);
				my $vid = $dev->get_vlan_membership($p);
				next unless exists $map->{$vid->[0]}; 
				push @{$data->{$s}->{$vid->[0]}}, $p;	

			}
		}
	}
	return $data;	
}




