# $Header: /tmp/netpass/NetPass/lib/SNMP/Device.pm,v 1.3 2005/03/05 04:14:18 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package SNMP::Device;

use Socket;
use Net::SNMP;
use Error qw(:try);
use strict;

=head1 NAME

SNMP::Device - Device-specific SNMP Controls

=head1 SYNOPSIS

When a new SNMP::Device is created, it will return an
object of this type if it's appropriate.

perldoc the associated plugins for device specific functions.

=head1 SYNOPSIS

use SNMP::Device;

my $dev = new SNMP::Device (
                                        'hostname'       => $ip,
                                        'snmp_community' => $comm,
					['sys_desc'	 => $sys_desc]
                                    );

print $dev->log . "\n" if($dev->log);

print $dev->err . "\n" if($dev->err);


=head1 PUBLIC METHODS

=cut


sub AUTOLOAD {
	no strict;
	return if($AUTOLOAD =~ /::DESTROY$/);
 	if ($AUTOLOAD=~/(\w+)$/) {
   		my $field = $1;
   		*{$field} = sub {
     				my $self = shift;
     				@_ ? $self->{"_$field"} = shift
       				   : $self->{"_$field"};
   				};
   		&$field(@_);
 	} else {
   		die("Cannot figure out field name from '$AUTOLOAD'");
 	}
}


sub new {
	my($class,%param) = @_;

    	my $self = {};
    	bless $self, ref($class) || $class;

    	$self->_initialize(%param);

	if($self->plugin) {
		$class = $self->plugin; 
		bless $self, ref($class) || $class;
    		$self->log("SNMP::Device has changed to a " . ref($self) . " object...");
	}

	# call optional init function in the plugin
	$self->init();
    
    	$self->log("Returning " . ref($self) . " object...");
    	return($self);
}

sub _initialize {
    
	my ($self, %opts) 	= @_;

	$self->log(ref($self) . "->_initialize()");

	# defaults
	$self->snmp_version('1');
	$self->snmp_timeout('60');
	$self->snmp_retry('3');
	$self->snmp_wait('5.0');
	$self->snmp_mtu('1500');
	$self->snmp_debug('0');
	$self->snmp_community('public');

	$self->device_type('');

        $self->file('[HOST].cfg');
        $self->err('');

	try {
		foreach my $k (keys %opts) {
			$self->$k($opts{$k});
		}

		$self->err("Hostname must be set!") if (!$self->hostname);

		return 0 if($self->err);
	
		$self->snmp();
		$self->plugin($self->_find_plugin());

	} catch Error::Simple with {
		my $error = shift;

		$self->err($error->{'-text'});
		return 0;

	};

}

########################################################

=head2 B<snmp()>

	Returns the Net::SNMP session object


=cut

sub snmp {
    	my($self) = @_;
	
	if(!$self->{'_snmp'}) {
		$self->{'_snmp'} = $self->_create_snmp();
	}

	return $self->{'_snmp'};
}

sub tftpserver {
    	my($self, $hostname) = @_;
	
	return $self->{'_tftpserver'} if(!$hostname);

	my $ip = $self->discover_host_address($hostname);
	$self->{'_tftpserver'} = $ip;

	return;
}

sub file {
    	my($self, $file) = @_;

	if(!$file) {
		my $f = $self->{'_file'};
		my $h = $self->hostname;
		$f =~ s/\[HOST\]/$h/g;
		return $f;
	}

	$self->{'_file'} = $file;

	return;
}

sub _create_snmp {
	my $self = shift;
	
	$self->log( ref($self) . "->_create_snmp()");

  	my %snmp_options = (
				-hostname	=> $self->ip,
				-version	=> $self->snmp_version,
				-retries	=> $self->snmp_retry,
				-timeout	=> $self->snmp_wait,
				-maxmsgsize	=> $self->snmp_mtu,
				-debug		=> $self->snmp_debug,
			   );

	if ( $snmp_options{'-version'} eq '3' ) {
    
  		## snmp v3 options
		$snmp_options{'-username'} 	= $self->snmp_user;
		$snmp_options{'-authkey'}  	= $self->snmp_authkey;
    		$snmp_options{'-authpassword'} 	= $self->snmp_authpasswd;

    		if ( $self->{'-snmp_authprotocol'} ) {

      			$snmp_options{'-authprotocol'}	= $self->snmp_authprotocol;
      			$snmp_options{'-privkey'}	= $self->snmp_authkey;
        		$snmp_options{'-privpassword'}	= $self->snmp_authpasswd;
    		}

  	} else {
    
  		## snmp v1/v2 options
    		$snmp_options{'-community'} = $self->snmp_community;
  	}

  	## initiate the session
  	my($snmp_session, $snmp_error) = Net::SNMP->session(%snmp_options);
  	
	die $self->hostname . " - Could not create SNMP session: $snmp_error" if(!defined($snmp_session));

	return $snmp_session;
}

sub _find_plugin {
	my $self    = shift;

	if(!defined($self->sys_desc)) {
		my %oid = (
				sysdesc => ".1.3.6.1.2.1.1.1.0"
		  	);

		$self->log(ref($self) . "->_find_plugin() - Getting device sys_descr");
	
   		my $result = $self->snmp->get_request($oid{'sysdesc'});

		if ($self->snmp->error) {
			$self->err("Couldn't connect via SNMP to " . $self->hostname . "! Error was: " . $self->snmp->error);
			return '';
		}
	
		my $desc  = $result->{$oid{'sysdesc'}};
                $desc = hex2string($desc) if ($desc =~ /^0x/);
		$self->sys_desc($desc);
	} else {
		$self->log(ref($self) . "->_find_plugin() - sys_descr was supplied in constructor");
	}

	my $plugin  = $self->map_desc_to_plugin($self->sys_desc);
   
	if($plugin) {
		$self->log("Plugin found for " . $self->hostname . " (" . $self->device_type . ")");
		eval "require $plugin";
	
		if ($@) {
			print STDERR "Cannot load plugin $plugin. Cause $@\n";
			return '';
		}

	} else {
		$self->err("Unable to determine plugin for " . $self->hostname . "! sysDesc: " . $self->sys_desc());
	}

	return $plugin; 

}

sub map_desc_to_plugin {
	my $self = shift;
	my $desc = shift;

	$self->log(ref($self) . "->_map_desc_to_plugin() - Searching for plugin matching $desc...");

	my $plugin = '';

        my $types = {
                        'Asante'        => {    'Desc'   => "Asante",
                                                'Module' => "SNMP::Device::Asante"
                                           },
                        'BayStack 350'  => {    'Desc'   => "BayStack 350",
                                                'Module' => "SNMP::Device::BayStack3"
                                           },
                        'BayStack 450'  => {    'Desc'   => "BayStack 450",
                                                'Module' => "SNMP::Device::BayStack"
                                           },
                        'BayStack 470'  => {    'Desc'   => "BayStack 470",
                                                'Module' => "SNMP::Device::BayStack"
                                           },
                        'BayStack 5510' => {    'Desc'   => "BayStack 5510",
                                                'Module' => "SNMP::Device::BayStack"
                                           },
                        'HP28688'       => {    'Desc'   => "HP28688 EtherTwist Hub PLUS",
                                                'Module' => "SNMP::Device::HP"
                                           },
                        'HP28699A'      => {    'Desc'   => "HP28699A EtherTwist Hub PLUS 48",
                                                'Module' => "SNMP::Device::HP"
                                           },
                        'HPJ2603A'      => {    'Desc'   => "HPJ3210A AdvanceStack Hub",
                                                'Module' => "SNMP::Device::HP_AS_HUB"
                                           },
                        'HPJ3210A'      => {    'Desc'   => "HPJ3210A AdvanceStack 10BT Switching Hub",
                                                'Module' => "SNMP::Device::HP_AS_SWITCH"
                                           },
                    };

	foreach my $k (keys %{$types}) {
		if($desc =~ /$k/) {
			$plugin = $types->{$k}->{'Module'};
			$self->device_type($types->{$k}->{'Desc'});
			last;
		}
   	}

	return $plugin;
}

sub hostname {
    	my($self, $hostname) = @_;

	return $self->{'_hostname'} if(!$hostname);

	my $ip = $self->discover_host_address($hostname);

	$self->{'_hostname'} = $hostname;
	$self->ip($ip);

	return;
}

=head2 B<log([$string])>

	Returns the current action log. If called with a parameter, it will
	append to the action log and then return it.

=cut

sub log {
    	my($self, $str) = @_;

	return $self->{'_log'} if(!$str);

	my $now_str = localtime;
	my $class   = ref($self);

	$self->{'_log'} .= "$now_str - $class - $str\n";

	return;
}

=head2 B<err([$string])>

	Returns the current error log. If called with a parameter, it will
	append to the error log and then return it.

=cut

sub err {
    	my($self, $str) = @_;

	return $self->{'_err'} if(!$str);

	my $now_str = localtime;
	my $class   = ref($self);

	$self->{'_err'} .= "$now_str - $class - $str\n";

	return;
}

sub discover_host_address {
	my $self     = shift;
	my $hostname = shift;

	if(!$hostname) { 
        	$self->err("Looks like this device doesn't have a hostname!"); 
		return 0;
	}

	my $ip = gethostbyname($hostname);
	
	if(!$ip) {
		$self->err("The following hostname could not be resolved: $hostname");
		return 0;
	}

	$ip = inet_ntoa($ip);
	return $ip;
}


#### LOOK AT THESE #########################
# perhaps changce get_unit_info to _get_unit_info

sub unit_info {
    	my $self = shift;
	
	$self->{'_unit_info'} = $self->get_unit_info if(!$self->{'_unit_info'});
	return $self->{'_unit_info'};
}

sub if_info {
    	my $self = shift;
	
	$self->{'_if_info'} = $self->get_if_info if(!$self->{'_if_info'});
	return $self->{'_if_info'};
}

sub port_status {
	my $self = shift;
	# OVERRIDE THIS FUNC!!!
	return 0;
}


=head1 SEE ALSO

	SNMP::Device::Asante
	SNMP::Device::BayStack3
	SNMP::Device::BayStack
	SNMP::Device::HP
	SNMP::Device::HP_AS_HUB
	SNMP::Device::HP_AS_SWITCH



=head1 AUTHOR

 Rob Colantuoni <rgc@buffalo.edu>
 Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: Device.pm,v 1.3 2005/03/05 04:14:18 jeffmurphy Exp $

=cut


sub hex2string {
        my $s = shift;
        return $s if (!defined($s) || ($s eq ""));
        my $ns = '';
        if ($s =~ /^0x([0-9a-f]+)$/i) {
                my $s2 = $1;
                for(my $_i = 0 ; $_i < length($s2) ; $_i += 2) {
                        $ns .= sprintf("%c", eval("0x".substr($s2, $_i, 2)));
                }
        }
        return $ns;
}




1;
